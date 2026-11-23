"""Unit tests for Industrial DNP3 / IEEE 1815-2012 Telemetry (W070 / Gate G8)."""

from __future__ import annotations

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.dnp3 import (
    DNP3CRC,
    DNP3Constants,
    DNP3DataCodec,
    DNP3Frame,
    DNP3Message,
    DNP3Outstation,
    DNP3TransportManager,
    DNP3_PURE_ST_POU,
    ApplicationControl,
    CROBObject,
    CROBOperationType,
    CROBStatusCode,
    FunctionCode,
    IIN2Flags,
    LinkControlOctet,
    PrimaryFunctionCode,
    SecondaryFunctionCode,
)


# ============================================================================
# 1. CRC & Framing Tests
# ============================================================================

def test_dnp3_crc16_standard_check_vector():
    """Verify IEEE 1815-2012 CRC-16 check value on standard ASCII '123456789'."""
    data = b"123456789"
    crc = DNP3CRC.calculate(data)
    assert crc == 0xEA82
    assert DNP3CRC.verify(data, 0xEA82) is True
    assert DNP3CRC.verify(data, 0x0000) is False


def test_dnp3_link_control_octet_bidirectional():
    """Verify Link Control Octet serialization and deserialization."""
    ctrl_tx = LinkControlOctet(
        direction=True,
        primary=True,
        fcb=True,
        fcv=True,
        dfc=False,
        function_code=PrimaryFunctionCode.CONFIRMED_USER_DATA,
    )
    b = ctrl_tx.to_byte()
    assert b == (0x80 | 0x40 | 0x20 | 0x10 | 0x03)
    ctrl_rx = LinkControlOctet.from_byte(b)
    assert ctrl_rx.direction is True
    assert ctrl_rx.primary is True
    assert ctrl_rx.fcb is True
    assert ctrl_rx.fcv is True
    assert ctrl_rx.function_code == PrimaryFunctionCode.CONFIRMED_USER_DATA


def test_dnp3_frame_build_and_parse_roundtrip():
    """Verify DNP3 Data Link frame serialization, chunking, and parsing."""
    ctrl = LinkControlOctet(
        direction=True,
        primary=True,
        fcb=False,
        fcv=False,
        function_code=PrimaryFunctionCode.UNCONFIRMED_USER_DATA,
    )
    payload = b"Hello DNP3 SCADA Telemetry 12345"  # 33 bytes -> 3 blocks (16, 16, 1)
    frame = DNP3Frame(control=ctrl, dest_address=10, source_address=1, user_data=payload)
    wire = frame.build()

    # Wire length: 10 (header) + 32 (data) + 2 blocks * 2 (CRCs) = 46 bytes
    assert len(wire) == 46
    parsed, consumed = DNP3Frame.parse(wire)
    assert consumed == 46
    assert parsed.dest_address == 10
    assert parsed.source_address == 1
    assert parsed.user_data == payload


def test_dnp3_frame_crc_corruption_detection():
    """Verify that corrupting bits in header or payload triggers CRC error."""
    ctrl = LinkControlOctet(direction=True, primary=True, function_code=PrimaryFunctionCode.RESET_LINK_STATES)
    frame = DNP3Frame(control=ctrl, dest_address=5, source_address=1, user_data=b"")
    wire = bytearray(frame.build())

    # Corrupt header CRC
    wire[9] ^= 0xFF
    with pytest.raises(ValueError, match="Header CRC mismatch"):
        DNP3Frame.parse(bytes(wire))


# ============================================================================
# 2. Transport & Application Layer Tests
# ============================================================================

def test_dnp3_transport_segmentation_and_reassembly():
    """Verify segmentation of APDUs larger than 249 bytes."""
    tm = DNP3TransportManager()
    big_apdu = bytes([i % 256 for i in range(500)])  # 500 bytes -> 3 segments (249, 249, 2)
    segments = tm.segment_apdu(big_apdu)
    assert len(segments) == 3

    rx_tm = DNP3TransportManager()
    assert rx_tm.reassemble_segment(segments[0]) is None
    assert rx_tm.reassemble_segment(segments[1]) is None
    reassembled = rx_tm.reassemble_segment(segments[2])
    assert reassembled == big_apdu


def test_dnp3_application_crob_select_operate_flow():
    """Verify CROB Select followed by Operate returns SUCCESS."""
    regs = RegisterTable()
    outstation = DNP3Outstation(station_address=10, master_address=1, registers=regs)
    ctrl = LinkControlOctet(direction=True, primary=True, function_code=PrimaryFunctionCode.UNCONFIRMED_USER_DATA)

    # 1. SELECT CROB
    crob = CROBObject(op_type=CROBOperationType.PULSE_ON, count=1, on_time_ms=500)
    sel_apdu = DNP3Message(
        ac=ApplicationControl(fir=True, fin=True, con=False, uns=False, seq=1),
        fc=FunctionCode.SELECT,
        objects=DNP3DataCodec.pack_g12v1_crob_request(0, crob),
    ).serialize()
    sel_segs = outstation.transport.segment_apdu(sel_apdu)
    sel_wire = DNP3Frame(control=ctrl, dest_address=10, source_address=1, user_data=sel_segs[0]).build()
    sel_resp = outstation.process_incoming_frame(sel_wire)
    assert sel_resp is not None
    assert regs.read_word("%R315") == CROBStatusCode.SUCCESS

    # 2. OPERATE CROB
    op_apdu = DNP3Message(
        ac=ApplicationControl(fir=True, fin=True, con=False, uns=False, seq=2),
        fc=FunctionCode.OPERATE,
        objects=DNP3DataCodec.pack_g12v1_crob_request(0, crob),
    ).serialize()
    op_segs = outstation.transport.segment_apdu(op_apdu)
    op_wire = DNP3Frame(control=ctrl, dest_address=10, source_address=1, user_data=op_segs[0]).build()
    op_resp = outstation.process_incoming_frame(op_wire)
    assert op_resp is not None
    assert regs.read_word("%R315") == CROBStatusCode.SUCCESS


def test_dnp3_application_crob_operate_without_select_fails():
    """Verify CROB Operate without Select returns NO_SELECT."""
    regs = RegisterTable()
    outstation = DNP3Outstation(station_address=10, master_address=1, registers=regs)
    ctrl = LinkControlOctet(direction=True, primary=True, function_code=PrimaryFunctionCode.UNCONFIRMED_USER_DATA)

    crob = CROBObject(op_type=CROBOperationType.PULSE_ON, count=1, on_time_ms=500)
    op_apdu = DNP3Message(
        ac=ApplicationControl(fir=True, fin=True, con=False, uns=False, seq=5),
        fc=FunctionCode.OPERATE,
        objects=DNP3DataCodec.pack_g12v1_crob_request(0, crob),
    ).serialize()
    op_segs = outstation.transport.segment_apdu(op_apdu)
    op_wire = DNP3Frame(control=ctrl, dest_address=10, source_address=1, user_data=op_segs[0]).build()
    op_resp = outstation.process_incoming_frame(op_wire)
    assert op_resp is not None
    assert regs.read_word("%R315") == CROBStatusCode.NO_SELECT


# ============================================================================
# 3. Pure ST POU & Forbidden Ladder Tests
# ============================================================================

def test_dnp3_pure_st_pou_ast_parsing_and_bindings():
    """Verify IEC 61131-3 Pure ST AST parsing and bound registers."""
    val = STParser.validate_code(DNP3_PURE_ST_POU)
    assert val.status == AgentStatus.SUCCESS
    ast = STParser.parse_pou(DNP3_PURE_ST_POU)
    assert ast.name == "Dnp3TelemetryParser"
    assert ast.pou_type == POUType.PROGRAM
    expected_registers = {"%R310", "%R311", "%R312", "%R313", "%R314", "%R315", "%M72", "%M73"}
    assert set(ast.bound_registers) == expected_registers


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
        "XIC EnableHandler",
        "XIO ResetCounters",
        "OTE StatusWord",
        "OTL BitActive",
        "OTU BitCrcError",
    ],
)
def test_dnp3_forbidden_ladder_constructs_rejected(ladder_token: str):
    """Verify ladder tokens are strictly rejected with ERR_LADDER_FORBIDDEN."""
    tainted = f"{DNP3_PURE_ST_POU}\n{ladder_token}"
    val = STParser.validate_code(tainted)
    assert val.status == AgentStatus.FAILED
    assert val.error_code == "ERR_LADDER_FORBIDDEN"
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(tainted)


def test_dnp3_register_handshake_reset():
    """Verify %M73 reset handshake clears counters and status word error bits."""
    regs = RegisterTable()
    outstation = DNP3Outstation(station_address=10, master_address=1, registers=regs)
    outstation.bit_crc_error = True
    outstation.frames_dropped = 5
    outstation._sync_registers()

    assert regs.read_word("%R312") == 5
    assert regs.read_word("%R310") & 0x0008 != 0

    # Pulse reset
    regs.write_bit("%M73", True, privilege=PrivilegeMode.SYSTEM)
    outstation._sync_registers()

    assert regs.read_word("%R312") == 0
    assert regs.read_word("%R310") & 0x0008 == 0
    assert regs.read_bit("%M73") is False
