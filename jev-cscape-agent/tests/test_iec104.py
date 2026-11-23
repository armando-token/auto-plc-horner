"""Unit and integration tests for IEC 60870-5-104 Telemetry Server.

Work Package: W073 (Gate G8 / G4)
Verifies:
- CP56Time2a 7-octet timestamp encoding and decoding
- APCI Framing: U-format (STARTDT/STOPDT/TESTFR), S-format, I-format
- ASDU Codecs: Type 1, Type 30, Type 13, Type 36, Type 45, Type 100
- Server Engine: General Interrogation, Select-Before-Operate commands, spontaneous events
- Pure ST POU syntax and AST parsing with Horner OCS register bindings
- Hard fail-closed rejection of forbidden ladder logic constructs
"""

from __future__ import annotations

import datetime
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import RegisterTable
from jev_cscape.telemetry.iec104 import (
    APCIFormat,
    CP56Time2a,
    IEC104ServerEngine,
    IEC104_SERVER_ST_CODE,
    IFrame,
    QDS,
    SCO,
    SIQ,
    SFrame,
    UFrame,
    UFunction,
    decode_asdu_type1,
    decode_asdu_type13,
    decode_asdu_type30,
    decode_asdu_type36,
    decode_asdu_type45,
    decode_asdu_type100,
    deserialize_apci,
    encode_asdu_type1,
    encode_asdu_type13,
    encode_asdu_type30,
    encode_asdu_type36,
    encode_asdu_type45,
    encode_asdu_type100,
    pack_ioa,
    unpack_ioa,
)


def test_cp56time2a_roundtrip() -> None:
    """Verify CP56Time2a encodes to exactly 7 octets and decodes back with millisecond fidelity."""
    original_dt = datetime.datetime(2026, 10, 3, 14, 30, 45, 123000)
    ts = CP56Time2a(dt=original_dt, invalid=False, summer_time=True)
    raw = ts.encode()
    assert len(raw) == 7

    decoded = CP56Time2a.decode(raw, century_base=2000)
    assert decoded.dt.year == 2026
    assert decoded.dt.month == 10
    assert decoded.dt.day == 3
    assert decoded.dt.hour == 14
    assert decoded.dt.minute == 30
    assert decoded.dt.second == 45
    assert decoded.dt.microsecond == 123000
    assert decoded.summer_time is True
    assert decoded.invalid is False


def test_ioa_packing() -> None:
    """Verify 24-bit IOA packing and unpacking."""
    assert pack_ioa(0) == b"\x00\x00\x00"
    assert pack_ioa(1001) == b"\xe9\x03\x00"
    assert unpack_ioa(b"\xe9\x03\x00") == 1001
    assert unpack_ioa(b"\xff\xff\x00") == 65535


def test_apci_u_frames() -> None:
    """Verify U-format frames (STARTDT, STOPDT, TESTFR) serialization and deserialization."""
    u_start = UFrame(function=UFunction.STARTDT_ACT)
    raw = u_start.serialize()
    assert len(raw) == 6
    assert raw[0] == 0x68
    assert raw[1] == 0x04
    assert raw[2] == 0x07

    parsed = deserialize_apci(raw)
    assert isinstance(parsed, UFrame)
    assert parsed.format == APCIFormat.U_FORMAT
    assert parsed.function == UFunction.STARTDT_ACT


def test_apci_s_frames() -> None:
    """Verify S-format frames for supervisory flow control."""
    s_frame = SFrame(recv_seq=42)
    raw = s_frame.serialize()
    assert len(raw) == 6
    assert raw[0] == 0x68
    assert raw[1] == 0x04
    assert raw[2] == 0x01
    assert raw[3] == 0x00

    parsed = deserialize_apci(raw)
    assert isinstance(parsed, SFrame)
    assert parsed.recv_seq == 42


def test_apci_i_frames() -> None:
    """Verify I-format frames carrying application payload."""
    asdu_sample = b"\x01\x02\x03\x04"
    i_frame = IFrame(send_seq=10, recv_seq=5, asdu=asdu_sample)
    raw = i_frame.serialize()
    assert len(raw) == 10
    assert raw[0] == 0x68
    assert raw[1] == 8  # 4 control octets + 4 ASDU octets

    parsed = deserialize_apci(raw)
    assert isinstance(parsed, IFrame)
    assert parsed.send_seq == 10
    assert parsed.recv_seq == 5
    assert parsed.asdu == asdu_sample


def test_asdu_type1_and_type30() -> None:
    """Verify Type 1 (Single-Point) and Type 30 (Single-Point with CP56Time2a)."""
    # Type 1
    raw_t1 = encode_asdu_type1(objects=[(1001, SIQ(value=True))], common_addr=1)
    hdr1, objs1 = decode_asdu_type1(raw_t1)
    assert hdr1.type_id == 1
    assert len(objs1) == 1
    assert objs1[0][0] == 1001
    assert objs1[0][1].value is True

    # Type 30
    now = datetime.datetime(2026, 10, 3, 12, 0, 0)
    ts = CP56Time2a(dt=now)
    raw_t30 = encode_asdu_type30(objects=[(1002, SIQ(value=False), ts)], common_addr=1)
    hdr30, objs30 = decode_asdu_type30(raw_t30)
    assert hdr30.type_id == 30
    assert len(objs30) == 1
    assert objs30[0][0] == 1002
    assert objs30[0][1].value is False
    assert objs30[0][2].dt == now


def test_asdu_type13_and_type36() -> None:
    """Verify Type 13 (Float32) and Type 36 (Float32 with CP56Time2a)."""
    # Type 13
    raw_t13 = encode_asdu_type13(objects=[(2001, 74.25, QDS())], common_addr=1)
    hdr13, objs13 = decode_asdu_type13(raw_t13)
    assert hdr13.type_id == 13
    assert len(objs13) == 1
    assert objs13[0][0] == 2001
    assert abs(objs13[0][1] - 74.25) < 1e-3

    # Type 36
    now = datetime.datetime(2026, 10, 3, 12, 0, 0)
    ts = CP56Time2a(dt=now)
    raw_t36 = encode_asdu_type36(objects=[(2002, 123.45, QDS(overflow=True), ts)], common_addr=1)
    hdr36, objs36 = decode_asdu_type36(raw_t36)
    assert hdr36.type_id == 36
    assert len(objs36) == 1
    assert objs36[0][0] == 2002
    assert abs(objs36[0][1] - 123.45) < 1e-2
    assert objs36[0][2].overflow is True


def test_asdu_type45_and_type100() -> None:
    """Verify Type 45 (Single Command) and Type 100 (General Interrogation)."""
    # Type 45 Select
    raw_t45_sel = encode_asdu_type45(ioa=3001, sco=SCO(state=True, select=True), cause=6)
    hdr45, ioa, sco = decode_asdu_type45(raw_t45_sel)
    assert hdr45.type_id == 45
    assert ioa == 3001
    assert sco.state is True
    assert sco.select is True

    # Type 100 Interrogation
    raw_t100 = encode_asdu_type100(qoi=20, ioa=0, cause=6)
    hdr100, ioa_qoi, qoi = decode_asdu_type100(raw_t100)
    assert hdr100.type_id == 100
    assert ioa_qoi == 0
    assert qoi == 20


def test_server_engine_full_gi_sequence() -> None:
    """Verify full connection startup and General Interrogation flow."""
    engine = IEC104ServerEngine(common_addr=1)
    engine.measured_analog_pv1 = 7500  # 75.00%

    # 1. STARTDT Act
    u_start = UFrame(function=UFunction.STARTDT_ACT).serialize()
    resp_start = engine.process_incoming_apdu(u_start)
    assert len(resp_start) == 1
    parsed_start_con = deserialize_apci(resp_start[0])
    assert isinstance(parsed_start_con, UFrame)
    assert parsed_start_con.function == UFunction.STARTDT_CON
    assert engine.startdt_active is True

    # 2. General Interrogation ASDU 100
    gi_req = encode_asdu_type100(qoi=20, ioa=0, cause=6, common_addr=1)
    iframe_gi = IFrame(send_seq=0, recv_seq=0, asdu=gi_req).serialize()
    resp_gi = engine.process_incoming_apdu(iframe_gi)

    # Expected: S-frame ack + ActCon + SP Data + ME Data + ActTerm = 5 frames
    assert len(resp_gi) == 5
    assert isinstance(deserialize_apci(resp_gi[0]), SFrame)

    # Check ActCon
    f1 = deserialize_apci(resp_gi[1])
    assert isinstance(f1, IFrame)
    hdr_con, _, _ = decode_asdu_type100(f1.asdu)
    assert hdr_con.cause == 7  # ActCon

    # Check ActTerm
    f4 = deserialize_apci(resp_gi[4])
    assert isinstance(f4, IFrame)
    hdr_term, _, _ = decode_asdu_type100(f4.asdu)
    assert hdr_term.cause == 10  # ActTerm


def test_server_engine_single_command_sbo() -> None:
    """Verify Select-Before-Operate command flow updates status and registers."""
    engine = IEC104ServerEngine(common_addr=1)

    # 1. Select Command
    cmd_sel = encode_asdu_type45(ioa=3001, sco=SCO(state=True, select=True), cause=6)
    iframe_sel = IFrame(send_seq=0, recv_seq=0, asdu=cmd_sel).serialize()
    resp_sel = engine.process_incoming_apdu(iframe_sel)
    assert len(resp_sel) == 2  # S-frame ack + ActCon
    assert engine.single_cmd_status == 2  # Select (Armed)

    # 2. Execute Command
    cmd_exec = encode_asdu_type45(ioa=3001, sco=SCO(state=True, select=False), cause=6)
    iframe_exec = IFrame(send_seq=1, recv_seq=1, asdu=cmd_exec).serialize()
    resp_exec = engine.process_incoming_apdu(iframe_exec)
    assert len(resp_exec) == 2
    assert engine.single_cmd_status == 1  # Execute


def test_server_engine_spontaneous_event() -> None:
    """Verify spontaneous event emission produces Type 30 ASDU with timestamp."""
    engine = IEC104ServerEngine(common_addr=1)
    evt_bytes = engine.emit_spontaneous_event(ioa=1005, value=True)
    frame = deserialize_apci(evt_bytes)
    assert isinstance(frame, IFrame)
    hdr, objs = decode_asdu_type30(frame.asdu)
    assert hdr.type_id == 30
    assert hdr.cause == 3  # Spontaneous
    assert len(objs) == 1
    assert objs[0][0] == 1005
    assert objs[0][1].value is True


def test_pure_st_pou_ast_parsing_and_bindings() -> None:
    """Verify IEC 61131-3 Pure ST POU validates and parses with bound registers."""
    val_res = STParser.validate_code(IEC104_SERVER_ST_CODE)
    assert val_res.status == AgentStatus.SUCCESS
    assert val_res.error_code is None

    ast = STParser.parse_pou(IEC104_SERVER_ST_CODE)
    assert ast.name == "Iec104TelemetryServer"
    assert ast.pou_type == POUType.PROGRAM
    expected_registers = {"%R340", "%R341", "%R342", "%R343", "%R344", "%R345", "%M79", "%M80"}
    assert expected_registers.issubset(set(ast.bound_registers))


@pytest.mark.parametrize(
    "ladder_artifact",
    [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(S)---",
        "---(R)---",
        "RUNG 1",
        "END_RUNG",
        "NETWORK 10",
        "XIC EnableServer",
        "XIO TriggerSpontaneous",
        "OTE StatusWord",
        "OTL BitServerActive",
        "OTU BitProtocolError",
    ],
)
def test_forbidden_ladder_constructs_rejected(ladder_artifact: str) -> None:
    """Verify any ladder construct is hard-rejected with ERR_LADDER_FORBIDDEN."""
    bad_code = f"{IEC104_SERVER_ST_CODE}\n{ladder_artifact}\n"
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_code)
    res = STParser.validate_code(bad_code)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ERR_LADDER_FORBIDDEN"
    assert res.data["ladder_rejected"] is True


def test_register_table_sync() -> None:
    """Verify register table synchronization and spontaneous trigger clearing."""
    table = RegisterTable()
    engine = IEC104ServerEngine(common_addr=1)

    table.write_register("%M79", True)
    table.write_register("%M80", True)  # Trigger spontaneous
    table.write_register("%R344", 8200)

    engine.sync_from_registers(table)
    assert engine.measured_analog_pv1 == 8200
    assert table.read_register("%M80") is False  # Self-cleared
    assert engine.frames_sent_counter >= 1

    engine.sync_to_registers(table)
    assert table.read_register("%R340") & 0x0001 != 0  # Active bit
    assert table.read_register("%R344") == 8200
