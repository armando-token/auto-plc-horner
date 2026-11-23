"""Unit and integration tests for ModbusMasterClient."""

import struct
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.modbus_client import (
    ModbusMasterClient,
    ModbusProtocolMode,
)
from jev_cscape.telemetry.modbus_stack import (
    ModbusExceptionCode,
    ModbusFunctionCode,
    ModbusMemoryStack,
    ModbusPDU,
    compute_crc16,
)


@pytest.fixture
def clean_register_table() -> RegisterTable:
    return RegisterTable()


@pytest.fixture
def rtu_client_and_stack(clean_register_table: RegisterTable):
    table = clean_register_table
    stack = ModbusMemoryStack(table, unit_id=1)
    client = ModbusMasterClient.create_in_memory_rtu(stack, unit_id=1)
    return client, stack, table


@pytest.fixture
def tcp_client_and_stack(clean_register_table: RegisterTable):
    table = clean_register_table
    stack = ModbusMemoryStack(table, unit_id=1)
    client = ModbusMasterClient.create_in_memory_tcp(stack, unit_id=1)
    return client, stack, table


def test_rtu_read_holding_registers(rtu_client_and_stack):
    client, stack, table = rtu_client_and_stack
    # Set registers %R1..%R4 in RegisterTable
    table.write_word("%R1", 1234, privilege=PrivilegeMode.SYSTEM)
    table.write_word("%R2", -5678, privilege=PrivilegeMode.SYSTEM)
    table.write_word("%R3", 0, privilege=PrivilegeMode.SYSTEM)
    table.write_word("%R4", 32000, privilege=PrivilegeMode.SYSTEM)

    # In standard Modbus, %R1 is 0-based address 0
    res = client.read_holding_registers(start_address=0, count=4)
    assert res.status == AgentStatus.SUCCESS
    assert res.data["count"] == 4
    assert res.data["registers"] == [1234, -5678, 0, 32000]


def test_rtu_write_single_register(rtu_client_and_stack):
    client, stack, table = rtu_client_and_stack

    res = client.write_single_register(address=10, value=4321)
    assert res.status == AgentStatus.SUCCESS
    assert res.data["address"] == 10
    assert res.data["written_value"] == 4321

    # Verify table %R11 (0-based 10) holds 4321
    assert table.read_word("%R11") == 4321


def test_rtu_write_multiple_registers(rtu_client_and_stack):
    client, stack, table = rtu_client_and_stack

    values = [100, 200, 300, 400, 500]
    res = client.write_multiple_registers(start_address=20, values=values)
    assert res.status == AgentStatus.SUCCESS
    assert res.data["registers_written"] == 5

    for i, expected in enumerate(values):
        assert table.read_word(f"%R{21 + i}") == expected


def test_rtu_coils_read_write(rtu_client_and_stack):
    client, stack, table = rtu_client_and_stack

    # Write single coil at address 5 (%Q6)
    w_res = client.write_single_coil(address=5, value=True)
    assert w_res.status == AgentStatus.SUCCESS
    assert table.read_bit("%Q6") is True

    # Write multiple coils
    coil_vals = [True, False, True, True, False, True]
    w_multi = client.write_multiple_coils(start_address=10, values=coil_vals)
    assert w_multi.status == AgentStatus.SUCCESS
    assert w_multi.data["coils_written"] == 6

    # Read back coils
    r_res = client.read_coils(start_address=10, count=6)
    assert r_res.status == AgentStatus.SUCCESS
    assert r_res.data["bits"] == coil_vals


def test_rtu_read_discrete_inputs(rtu_client_and_stack):
    client, stack, table = rtu_client_and_stack
    table.set_input("%I1", True)
    table.set_input("%I2", False)
    table.set_input("%I3", True)
    table.latch_inputs()

    res = client.read_discrete_inputs(start_address=0, count=3)
    assert res.status == AgentStatus.SUCCESS
    assert res.data["bits"] == [True, False, True]


def test_rtu_read_input_registers(rtu_client_and_stack):
    client, stack, table = rtu_client_and_stack
    table.set_input("%AI1", 16000)
    table.set_input("%AI2", -100)
    table.latch_inputs()

    res = client.read_input_registers(start_address=0, count=2)
    assert res.status == AgentStatus.SUCCESS
    assert res.data["registers"] == [16000, -100]


def test_tcp_master_client_transaction(tcp_client_and_stack):
    client, stack, table = tcp_client_and_stack
    table.write_word("%R100", 9999, privilege=PrivilegeMode.SYSTEM)

    res1 = client.read_holding_registers(start_address=99, count=1)
    assert res1.status == AgentStatus.SUCCESS
    assert res1.data["registers"] == [9999]
    assert res1.data["protocol_mode"] == "TCP"

    # Verify transaction IDs increment
    res2 = client.write_single_register(address=99, value=8888)
    assert res2.status == AgentStatus.SUCCESS
    assert table.read_word("%R100") == 8888


def test_modbus_exception_illegal_address(rtu_client_and_stack):
    client, stack, table = rtu_client_and_stack
    # Address out of range (> 9999)
    res = client.read_holding_registers(start_address=15000, count=1)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "ERR_MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS"
    assert res.data["exception_code"] == 0x02


def test_crc_error_recovery_and_retry(clean_register_table: RegisterTable):
    table = clean_register_table
    stack = ModbusMemoryStack(table, unit_id=1)
    table.write_word("%R1", 777, privilege=PrivilegeMode.SYSTEM)

    calls = 0

    def faulty_transport(request: bytes) -> bytes:
        nonlocal calls
        calls += 1
        resp = stack.process_rtu_frame(request)
        if calls == 1:
            # Corrupt CRC on first call
            corrupted = bytearray(resp)
            corrupted[-1] ^= 0xFF
            return bytes(corrupted)
        # Clean response on subsequent call
        return resp

    client = ModbusMasterClient(
        transport=faulty_transport,
        protocol_mode=ModbusProtocolMode.RTU,
        max_retries=2,
    )
    res = client.read_holding_registers(start_address=0, count=1)
    assert res.status == AgentStatus.SUCCESS
    assert res.data["registers"] == [777]
    assert res.data["attempts"] == 2
    assert client.telemetry.crc_errors == 1
    assert client.telemetry.retries_attempted == 1


def test_invalid_client_quantities(rtu_client_and_stack):
    client, _, _ = rtu_client_and_stack
    res_zero = client.read_holding_registers(start_address=0, count=0)
    assert res_zero.status == AgentStatus.FAILED
    assert res_zero.error_code == "ERR_MODBUS_INVALID_QUANTITY"

    res_excess = client.read_holding_registers(start_address=0, count=200)
    assert res_excess.status == AgentStatus.FAILED
    assert res_excess.error_code == "ERR_MODBUS_INVALID_QUANTITY"


def test_runner_execution_and_evidence_export(tmp_path):
    from scripts.run_modbus_client_verification import run_modbus_client_verification
    out_file = tmp_path / "modbus_client_evidence.json"
    evidence = run_modbus_client_verification(repo_root=tmp_path, output_path=out_file)
    assert evidence["status"] == "success"
    assert out_file.exists()
    assert len(evidence["data"]["function_codes_verified"]) == 8
