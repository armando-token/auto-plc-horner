"""Unit Tests for Industrial IO-Link Master Protocol Frame Engine (W100).

Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation.
"""

from __future__ import annotations

import struct
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.io_link import (
    IOLinkBaudRate,
    PortState,
    MSequenceType,
    IOLinkMasterStatusBits,
    ISDUErrorCode,
    compute_io_link_checksum,
    DirectParameterPage1,
    IOLinkDeviceModel,
    PortChannel,
    IOLinkMasterEngine,
    IO_LINK_PURE_ST_POU,
    run_io_link_verification,
)


class TestIOLinkMasterEngine:
    """Test suite for W100 IO-Link Master Protocol Frame Engine."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify Pure ST POU validation and AST symbol bindings."""
        SecurityGuard.assert_pure_st_content(IO_LINK_PURE_ST_POU)
        res = STParser.validate_code(IO_LINK_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(IO_LINK_PURE_ST_POU)
        assert ast.name == "IOLinkMasterPortSync"
        assert ast.pou_type == POUType.PROGRAM
        assert "%R610" in ast.bound_registers
        assert "%R611" in ast.bound_registers
        assert "%R612" in ast.bound_registers
        assert "%R613" in ast.bound_registers
        assert "%R614" in ast.bound_registers
        assert "%R615" in ast.bound_registers
        assert "%R616" in ast.bound_registers
        assert "%R617" in ast.bound_registers
        assert "%M142" in ast.bound_registers
        assert "%M143" in ast.bound_registers

    def test_ladder_construct_interception(self) -> None:
        """Verify ladder contacts and coils are intercepted fail-closed."""
        bad_st = """
        PROGRAM BadIOLinkLadder
        VAR PortBit : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_checksum_calculation_and_bit_flip_detection(self) -> None:
        """Verify 6-bit CKT checksum calculation and bit-flip sensitivity."""
        payload1 = b"\x01\x02\x03\x04"
        chk1 = compute_io_link_checksum(payload1, seed=0x52)
        assert 0 <= chk1 <= 63

        # Identical payload produces same checksum
        assert compute_io_link_checksum(payload1, seed=0x52) == chk1

        # 1-bit corruption alters checksum
        payload_corrupted = b"\x01\x02\x03\x05"
        chk2 = compute_io_link_checksum(payload_corrupted, seed=0x52)
        assert chk1 != chk2

    def test_baud_rates_and_cycle_time_calculations(self) -> None:
        """Verify baud rate bit times and minimum transaction durations."""
        assert pytest.approx(IOLinkMasterEngine.get_bit_time_us(IOLinkBaudRate.COM1), 0.1) == 208.33
        assert pytest.approx(IOLinkMasterEngine.get_bit_time_us(IOLinkBaudRate.COM2), 0.1) == 26.04
        assert pytest.approx(IOLinkMasterEngine.get_bit_time_us(IOLinkBaudRate.COM3), 0.1) == 4.34

        t_com3 = IOLinkMasterEngine.calculate_min_cycle_time_us(IOLinkBaudRate.COM3, 2, 2)
        t_com1 = IOLinkMasterEngine.calculate_min_cycle_time_us(IOLinkBaudRate.COM1, 2, 2)

        # 4 bytes total (2 Mst + 2 Dev) * 11 bits = 44 bits + 4 bits turnaround = 48 bits * 4.34 us = ~208.3 us
        assert 150.0 < t_com3 < 300.0
        assert t_com1 > 5000.0

    def test_port_lifecycle_transitions(self) -> None:
        """Verify port state transitions from NO_DEVICE to OPERATE."""
        reg_table = RegisterTable()
        master = IOLinkMasterEngine(register_table=reg_table, master_cycle_time_us=2500)

        # Invalid port attach
        res_inv = master.attach_device(99, IOLinkDeviceModel(port_id=1))
        assert res_inv.status == AgentStatus.FAILED

        # Port 1 attach
        dev1 = IOLinkDeviceModel(port_id=1, baud_rate=IOLinkBaudRate.COM3)
        res_att = master.attach_device(1, dev1)
        assert res_att.status == AgentStatus.SUCCESS
        assert master.ports[1].state == PortState.PRE_OPERATE

        # Transition to OPERATE
        res_op = master.transition_to_operate(1)
        assert res_op.status == AgentStatus.SUCCESS
        assert master.ports[1].state == PortState.OPERATE
        assert master.compute_active_port_mask() == 0x01

        # Incompatible revision check
        dev_bad = IOLinkDeviceModel(
            port_id=2,
            dpp1=DirectParameterPage1(revision_id=0x99),
        )
        master.attach_device(2, dev_bad)
        res_bad_rev = master.transition_to_operate(2)
        assert res_bad_rev.status == AgentStatus.FAILED
        assert master.ports[2].state == PortState.REVISION_INCOMPATIBLE

    def test_isdu_parameter_exchange(self) -> None:
        """Verify acyclic ISDU Read, Write, and error code handling."""
        master = IOLinkMasterEngine()
        dev = IOLinkDeviceModel(port_id=1)
        master.attach_device(1, dev)

        # Read Vendor Name
        res_rd, val_vendor = master.isdu_read(1, 0x0010)
        assert res_rd.status == AgentStatus.SUCCESS
        assert val_vendor == b"Horner APG"

        # Attempt to overwrite read-only identity parameter (0x0010)
        res_wr_ro = master.isdu_write(1, 0x0010, 0, b"Other Corp")
        assert res_wr_ro.status == AgentStatus.FAILED
        assert res_wr_ro.error_code == "ERR_ISDU_READ_ONLY"

        # Write custom configuration parameter
        res_wr_valid = master.isdu_write(1, 0x0040, 0, struct.pack(">H", 6500))
        assert res_wr_valid.status == AgentStatus.SUCCESS

        res_rd_valid, val_param = master.isdu_read(1, 0x0040)
        assert res_rd_valid.status == AgentStatus.SUCCESS
        assert struct.unpack(">H", val_param)[0] == 6500

        # Read non-existent index
        res_missing, _ = master.isdu_read(1, 0xFFFF)
        assert res_missing.status == AgentStatus.FAILED
        assert res_missing.error_code == "ERR_ISDU_IDX_NOTAVAIL"

        # Write payload length overrun (> 232 octets)
        res_overrun = master.isdu_write(1, 0x0040, 0, b"X" * 250)
        assert res_overrun.status == AgentStatus.FAILED
        assert res_overrun.error_code == "ERR_ISDU_LENGTH_OVERRUN"

    def test_cyclic_process_data_exchange(self) -> None:
        """Verify cyclic process data buffer mapping to registers."""
        reg_table = RegisterTable()
        master = IOLinkMasterEngine(register_table=reg_table)

        dev1 = IOLinkDeviceModel(port_id=1)
        dev2 = IOLinkDeviceModel(port_id=2)
        master.attach_device(1, dev1)
        master.transition_to_operate(1)
        master.attach_device(2, dev2)
        master.transition_to_operate(2)

        # Cyclic scan with inputs
        res_scan = master.execute_scan_cycle(port_inputs={1: 2845, 2: 9120})
        assert res_scan.status == AgentStatus.SUCCESS
        assert reg_table.read_word("%R612") == 2845
        assert reg_table.read_word("%R613") == 9120
        assert reg_table.read_word("%R611") == 0x0003

        # Scan with checksum error injection
        res_err = master.execute_scan_cycle(inject_checksum_error=True)
        assert res_err.status == AgentStatus.FAILED
        assert master.total_checksum_errors == 1
        assert (reg_table.read_word("%R610") & int(IOLinkMasterStatusBits.CHECKSUM_FAULT)) != 0

    def test_port_fault_injection_and_reset(self) -> None:
        """Verify wire break and short circuit fault injection and latch clearing."""
        reg_table = RegisterTable()
        master = IOLinkMasterEngine(register_table=reg_table)
        dev = IOLinkDeviceModel(port_id=1)
        master.attach_device(1, dev)
        master.transition_to_operate(1)

        # Inject short circuit
        master.inject_port_fault(1, PortState.SHORT_CIRCUIT, event_code=0x8C10)
        assert master.ports[1].state == PortState.SHORT_CIRCUIT
        assert reg_table.read_bit("%M143") is True
        assert (reg_table.read_word("%R610") & int(IOLinkMasterStatusBits.SHORT_CIRCUIT_ALARM)) != 0
        assert (reg_table.read_word("%R617") & 0xFFFF) == 0x8C10

        # Reset fault
        res_reset = master.reset_port_fault(1)
        assert res_reset.status == AgentStatus.SUCCESS
        assert master.ports[1].state == PortState.PRE_OPERATE
        assert master.ports[1].diagnostic_code == 0x0000

    def test_horner_register_sync(self) -> None:
        """Verify register mappings %R610..%R617 and %M142..%M143."""
        reg_table = RegisterTable()
        master = IOLinkMasterEngine(register_table=reg_table, master_cycle_time_us=3000)

        # Initially no operate
        assert reg_table.read_bit("%M142") is False
        assert reg_table.read_bit("%M143") is False
        assert reg_table.read_word("%R614") == 3000

        # Attach and operate
        dev = IOLinkDeviceModel(port_id=1)
        master.attach_device(1, dev)
        master.transition_to_operate(1)

        assert reg_table.read_bit("%M142") is True
        assert (reg_table.read_word("%R610") & int(IOLinkMasterStatusBits.MASTER_OPERATE)) != 0

    def test_full_verification_runner_9_stages(self) -> None:
        """Verify 9-stage verification suite executes and passes all checks."""
        evidence = run_io_link_verification()
        assert evidence["status"] == "success"
        assert evidence["data"]["checks_passed"] == 9
        assert evidence["data"]["total_checks"] == 9
