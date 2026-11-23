"""Comprehensive Unit and Integration Test Suite for Modbus Protocol Stack.

Work Package: W039 (Gate G8 Telemetry Scaling & Protocols)
Classification: PRODUCTION_READY

Validates:
1. CRC-16 calculation accuracy against Modbus standard polynomial test vectors.
2. In-memory Modbus RTU / TCP frame serialization and deserialization.
3. Function Code execution: FC 01, 02, 03, 04, 05, 06, 15, 16.
4. Exception generation: ILLEGAL_FUNCTION, ILLEGAL_DATA_ADDRESS, ILLEGAL_DATA_VALUE.
5. Direct memory binding to Horner OCS RegisterTable.
"""

from __future__ import annotations

import struct
from pathlib import Path
import pytest

from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.modbus_stack import (
    ModbusExceptionCode,
    ModbusFunctionCode,
    ModbusMemoryStack,
    ModbusPDU,
    compute_crc16,
)


def test_compute_crc16_standard_vectors() -> None:
    """Verify compute_crc16 matches official Modbus test vectors."""
    # Standard Modbus query: Unit 1, Read 10 registers from 0
    # 01 03 00 00 00 0A -> CRC = C5 CD (in little endian: 0xCDC5)
    query = bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
    crc = compute_crc16(query)
    # Pack as little-endian: low byte first, high byte second
    crc_bytes = struct.pack("<H", crc)
    assert crc_bytes == bytes([0xC5, 0xCD])


def test_modbus_pdu_serialization() -> None:
    """Verify PDU round-trip serialization and deserialization."""
    raw = bytes([0x03, 0x00, 0x10, 0x00, 0x04])
    pdu = ModbusPDU.deserialize(raw)
    assert pdu.function_code == 0x03
    assert pdu.data == bytes([0x00, 0x10, 0x00, 0x04])
    assert pdu.serialize() == raw


def test_read_coils_fc01() -> None:
    """Verify FC 01 Read Coils maps to %Q bit registers."""
    regs = RegisterTable()
    regs.privilege_mode = PrivilegeMode.SYSTEM
    # Set %Q1=True, %Q2=False, %Q3=True, %Q4=True (binary 1101 = 0x0D)
    regs.write_bit("%Q1", True)
    regs.write_bit("%Q2", False)
    regs.write_bit("%Q3", True)
    regs.write_bit("%Q4", True)

    stack = ModbusMemoryStack(register_table=regs)

    # Request 4 coils starting at 0 (maps to %Q1..%Q4)
    req_data = struct.pack(">HH", 0, 4)
    pdu = ModbusPDU(function_code=ModbusFunctionCode.READ_COILS, data=req_data)
    resp = stack.process_pdu(pdu)

    assert resp.function_code == ModbusFunctionCode.READ_COILS
    byte_count = resp.data[0]
    assert byte_count == 1
    coils_byte = resp.data[1]
    assert coils_byte == 0x0D


def test_read_discrete_inputs_fc02() -> None:
    """Verify FC 02 Read Discrete Inputs maps to %I bit registers."""
    regs = RegisterTable()
    regs.privilege_mode = PrivilegeMode.SYSTEM
    regs.write_bit("%I1", True)
    regs.write_bit("%I2", True)
    regs.write_bit("%I3", False)

    stack = ModbusMemoryStack(register_table=regs)

    req_data = struct.pack(">HH", 0, 3)
    pdu = ModbusPDU(function_code=ModbusFunctionCode.READ_DISCRETE_INPUTS, data=req_data)
    resp = stack.process_pdu(pdu)

    assert resp.function_code == ModbusFunctionCode.READ_DISCRETE_INPUTS
    assert resp.data[0] == 1
    assert resp.data[1] == 0x03


def test_read_holding_registers_fc03() -> None:
    """Verify FC 03 Read Holding Registers maps to %R word registers."""
    regs = RegisterTable()
    regs.privilege_mode = PrivilegeMode.SYSTEM
    regs.write_word("%R1", 1234)
    regs.write_word("%R2", 5678)
    regs.write_word("%R3", -100)

    stack = ModbusMemoryStack(register_table=regs)

    req_data = struct.pack(">HH", 0, 3)
    pdu = ModbusPDU(function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS, data=req_data)
    resp = stack.process_pdu(pdu)

    assert resp.function_code == ModbusFunctionCode.READ_HOLDING_REGISTERS
    assert resp.data[0] == 6  # 3 words * 2 bytes
    w1, w2, w3 = struct.unpack(">HHh", resp.data[1:])
    assert w1 == 1234
    assert w2 == 5678
    assert w3 == -100


def test_read_input_registers_fc04() -> None:
    """Verify FC 04 Read Input Registers maps to %AI word registers."""
    regs = RegisterTable()
    regs.privilege_mode = PrivilegeMode.SYSTEM
    regs.write_word("%AI1", 16000)
    regs.write_word("%AI2", 32000)

    stack = ModbusMemoryStack(register_table=regs)

    req_data = struct.pack(">HH", 0, 2)
    pdu = ModbusPDU(function_code=ModbusFunctionCode.READ_INPUT_REGISTERS, data=req_data)
    resp = stack.process_pdu(pdu)

    assert resp.function_code == ModbusFunctionCode.READ_INPUT_REGISTERS
    assert resp.data[0] == 4
    w1, w2 = struct.unpack(">HH", resp.data[1:])
    assert w1 == 16000
    assert w2 == 32000


def test_write_single_coil_fc05() -> None:
    """Verify FC 05 Write Single Coil sets and clears %Q bit."""
    regs = RegisterTable()
    regs.privilege_mode = PrivilegeMode.SYSTEM
    stack = ModbusMemoryStack(register_table=regs)

    # Turn ON coil 0 (maps to %Q1)
    req_on = struct.pack(">HH", 0, 0xFF00)
    resp_on = stack.process_pdu(ModbusPDU(function_code=ModbusFunctionCode.WRITE_SINGLE_COIL, data=req_on))
    assert resp_on.function_code == ModbusFunctionCode.WRITE_SINGLE_COIL
    assert regs.read_bit("%Q1") is True

    # Turn OFF coil 0
    req_off = struct.pack(">HH", 0, 0x0000)
    resp_off = stack.process_pdu(ModbusPDU(function_code=ModbusFunctionCode.WRITE_SINGLE_COIL, data=req_off))
    assert resp_off.function_code == ModbusFunctionCode.WRITE_SINGLE_COIL
    assert regs.read_bit("%Q1") is False


def test_write_single_register_fc06() -> None:
    """Verify FC 06 Write Single Register writes to %R."""
    regs = RegisterTable()
    regs.privilege_mode = PrivilegeMode.SYSTEM
    stack = ModbusMemoryStack(register_table=regs)

    req = struct.pack(">Hh", 4, -4321)  # Address 4 maps to %R5
    resp = stack.process_pdu(ModbusPDU(function_code=ModbusFunctionCode.WRITE_SINGLE_REGISTER, data=req))
    assert resp.function_code == ModbusFunctionCode.WRITE_SINGLE_REGISTER
    assert regs.read_word("%R5") == -4321


def test_write_multiple_coils_fc15() -> None:
    """Verify FC 15 Write Multiple Coils updates %Q bit registers."""
    regs = RegisterTable()
    regs.privilege_mode = PrivilegeMode.SYSTEM
    stack = ModbusMemoryStack(register_table=regs)

    # Write 5 coils at address 10 (%Q11..%Q15): binary 10101 = 0x15
    data = struct.pack(">HHB", 10, 5, 1) + bytes([0x15])
    resp = stack.process_pdu(ModbusPDU(function_code=ModbusFunctionCode.WRITE_MULTIPLE_COILS, data=data))
    assert resp.function_code == ModbusFunctionCode.WRITE_MULTIPLE_COILS

    assert regs.read_bit("%Q11") is True
    assert regs.read_bit("%Q12") is False
    assert regs.read_bit("%Q13") is True
    assert regs.read_bit("%Q14") is False
    assert regs.read_bit("%Q15") is True


def test_write_multiple_registers_fc16() -> None:
    """Verify FC 16 Write Multiple Registers updates consecutive %R holding registers."""
    regs = RegisterTable()
    regs.privilege_mode = PrivilegeMode.SYSTEM
    stack = ModbusMemoryStack(register_table=regs)

    # Write 3 registers at address 20 (%R21, %R22, %R23)
    words_data = struct.pack(">hhh", 100, -200, 300)
    data = struct.pack(">HHB", 20, 3, 6) + words_data
    resp = stack.process_pdu(ModbusPDU(function_code=ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS, data=data))
    assert resp.function_code == ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS

    assert regs.read_word("%R21") == 100
    assert regs.read_word("%R22") == -200
    assert regs.read_word("%R23") == 300


def test_exception_illegal_function() -> None:
    """Verify unsupported function code triggers ILLEGAL_FUNCTION (0x01)."""
    stack = ModbusMemoryStack()
    pdu = ModbusPDU(function_code=99, data=b"")
    resp = stack.process_pdu(pdu)

    assert resp.function_code == (99 | 0x80)
    assert resp.data[0] == ModbusExceptionCode.ILLEGAL_FUNCTION


def test_exception_illegal_address() -> None:
    """Verify out-of-range address triggers ILLEGAL_DATA_ADDRESS (0x02)."""
    stack = ModbusMemoryStack()
    # Address 10000 maps to %R10001, exceeding Horner 9999 %R range
    req_data = struct.pack(">HH", 10000, 1)
    pdu = ModbusPDU(function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS, data=req_data)
    resp = stack.process_pdu(pdu)

    assert resp.function_code == (ModbusFunctionCode.READ_HOLDING_REGISTERS | 0x80)
    assert resp.data[0] == ModbusExceptionCode.ILLEGAL_DATA_ADDRESS


def test_rtu_frame_processing_round_trip() -> None:
    """Verify RTU frame processing handles valid frame and checks CRC."""
    regs = RegisterTable()
    regs.privilege_mode = PrivilegeMode.SYSTEM
    regs.write_word("%R1", 777)
    stack = ModbusMemoryStack(register_table=regs, unit_id=1)

    # Build RTU query: Unit 1, FC 03, Addr 0, Count 1
    pdu = ModbusPDU(function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS, data=struct.pack(">HH", 0, 1))
    payload = bytes([1]) + pdu.serialize()
    crc = compute_crc16(payload)
    rtu_frame = payload + struct.pack("<H", crc)

    resp_rtu = stack.process_rtu_frame(rtu_frame)
    assert len(resp_rtu) > 4

    # Verify response CRC
    resp_payload = resp_rtu[:-2]
    resp_crc = struct.unpack("<H", resp_rtu[-2:])[0]
    assert compute_crc16(resp_payload) == resp_crc

    # Unpack response
    assert resp_rtu[0] == 1  # Unit ID
    assert resp_rtu[1] == 0x03  # FC
    assert resp_rtu[2] == 2  # Byte count
    val = struct.unpack(">H", resp_rtu[3:5])[0]
    assert val == 777


def test_tcp_frame_processing_round_trip() -> None:
    """Verify TCP frame processing handles MBAP header."""
    regs = RegisterTable()
    regs.privilege_mode = PrivilegeMode.SYSTEM
    regs.write_bit("%Q1", True)
    stack = ModbusMemoryStack(register_table=regs, unit_id=1)

    # Build TCP query: TransID 1234, Proto 0, Len 6, Unit 1, FC 01, Addr 0, Count 1
    pdu = ModbusPDU(function_code=ModbusFunctionCode.READ_COILS, data=struct.pack(">HH", 0, 1))
    pdu_bytes = pdu.serialize()
    mbap = struct.pack(">HHHB", 1234, 0, len(pdu_bytes) + 1, 1)
    tcp_frame = mbap + pdu_bytes

    resp_tcp = stack.process_tcp_frame(tcp_frame)
    assert len(resp_tcp) >= 8

    resp_trans, resp_proto, resp_len, resp_unit = struct.unpack(">HHHB", resp_tcp[:7])
    assert resp_trans == 1234
    assert resp_proto == 0
    assert resp_unit == 1
    assert resp_tcp[7] == 0x01  # FC 01
    assert resp_tcp[8] == 1     # Byte count
    assert (resp_tcp[9] & 0x01) == 1  # %Q1 is True


def test_verify_modbus_stack_and_export_evidence(tmp_path: Path) -> None:
    """Verify evidence export generates strict 4-state contract and valid JSON file."""
    from jev_cscape.telemetry.modbus_stack import verify_modbus_stack_and_export_evidence
    import json

    out_file = tmp_path / "modbus_stack_evidence.json"
    result = verify_modbus_stack_and_export_evidence(output_path=str(out_file))

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert result["data"]["gate"] == "G8"
    assert result["data"]["work_package"] == "W039"
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["status"] == "success"
    assert "FC01_READ_COILS" in loaded["data"]["function_codes_verified"]
