"""Unit tests for Industrial AS-Interface (AS-i v3.0 / IEC 62026-2) Master Protocol Engine (W103)."""

from __future__ import annotations

import pytest

from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import RegisterTable
from jev_cscape.telemetry.asi import (
    ASiCommandType,
    ASiDiagnosticCode,
    ASiMasterEngine,
    ASiMasterPhase,
    ASiMasterRequestFrame,
    ASiMasterStatusBits,
    ASiSafetyAtWorkMonitor,
    ASiSlaveBank,
    ASiSlaveDescriptor,
    ASiSlaveResponseFrame,
    SAW_NOMINAL_SEQUENCE,
    calculate_cycle_time_us,
    calculate_transaction_time_us,
    compute_master_request_pb,
    compute_slave_response_pb,
    verify_asi_pure_st,
)


def test_pure_st_pou_ast() -> None:
    """Stage 1: Verify Pure ST POU AST parsing and absence of ladder constructs."""
    assert verify_asi_pure_st() is True


def test_request_frame_encoding_decoding() -> None:
    """Stage 2: Verify 14-bit request frame encoding and decoding."""
    req = ASiMasterRequestFrame(
        command=ASiCommandType.DATA_EXCHANGE,
        address=12,
        info=0x0B,
        cb=0,
    )
    raw = req.encode_raw_word()
    assert 0 <= raw <= 0x3FFF

    # Check parity
    expected_pb = compute_master_request_pb(req.sb, req.cb, req.address, req.info)
    assert req.pb == expected_pb

    # Decode
    decoded, err = ASiMasterRequestFrame.decode_raw_word(raw)
    assert err == "OK"
    assert decoded is not None
    assert decoded.address == 12
    assert decoded.info == 0x0B
    assert decoded.cb == 0


def test_response_frame_encoding_decoding() -> None:
    """Stage 2: Verify 7-bit slave response frame encoding and decoding."""
    resp = ASiSlaveResponseFrame(info=0x0D)
    raw = resp.encode_raw_word()
    assert 0 <= raw <= 0x7F

    expected_pb = compute_slave_response_pb(resp.sb, resp.info)
    assert resp.pb == expected_pb

    decoded, err = ASiSlaveResponseFrame.decode_raw_word(raw)
    assert err == "OK"
    assert decoded is not None
    assert decoded.info == 0x0D


def test_frame_parity_and_framing_errors() -> None:
    """Stage 2: Verify detection of parity, start bit, end bit, and length violations."""
    req = ASiMasterRequestFrame(command=ASiCommandType.READ_STATUS, address=7, info=0x1D, cb=1)
    raw = req.encode_raw_word()

    # Corrupt parity
    corrupted_parity = raw ^ 0b00000000000010
    _, err_p = ASiMasterRequestFrame.decode_raw_word(corrupted_parity)
    assert err_p == "ERR_PARITY"

    # Corrupt start bit (make it 1)
    corrupted_sb = raw | (1 << 13)
    _, err_sb = ASiMasterRequestFrame.decode_raw_word(corrupted_sb)
    assert err_sb == "ERR_START_BIT"

    # Corrupt end bit (make it 0)
    corrupted_eb = raw & ~1
    _, err_eb = ASiMasterRequestFrame.decode_raw_word(corrupted_eb)
    assert err_eb == "ERR_END_BIT"

    # Frame length overflow
    _, err_len = ASiMasterRequestFrame.decode_raw_word(0x4000)
    assert err_len == "ERR_FRAME_LENGTH"


def test_timing_formulas() -> None:
    """Stage 3: Verify analytical transaction and cycle timing formulas."""
    tx_time = calculate_transaction_time_us()
    assert tx_time == pytest.approx(156.0, abs=1e-3)

    # 4 slaves + 2 management slots = 6 * 156 us = 936.0 us
    c_time_4 = calculate_cycle_time_us(4)
    assert c_time_4 == pytest.approx(936.0, abs=1e-3)

    # 31 slaves + 2 management slots = 33 * 156 us = 5148.0 us
    c_time_31 = calculate_cycle_time_us(31)
    assert c_time_31 == pytest.approx(5148.0, abs=1e-3)


def test_ab_slave_addressing() -> None:
    """Stage 3: Verify Extended A/B Addressing and register bitmasks."""
    master = ASiMasterEngine()
    s1a = ASiSlaveDescriptor(address=1, bank=ASiSlaveBank.BANK_A)
    s8a = ASiSlaveDescriptor(address=8, bank=ASiSlaveBank.BANK_A)
    s18a = ASiSlaveDescriptor(address=18, bank=ASiSlaveBank.BANK_A)
    s1b = ASiSlaveDescriptor(address=1, bank=ASiSlaveBank.BANK_B)

    master.add_configured_slave(s1a)
    master.add_configured_slave(s8a)
    master.add_configured_slave(s18a)
    master.add_configured_slave(s1b)

    master._sync_registers()
    assert master.reg_table.read_word("%R641") == 4

    # Low mask (Slaves 1..16): 1A is bit 0, 8A is bit 7 -> (1<<0) | (1<<7) = 1 + 128 = 129
    assert master.reg_table.read_word("%R642") == 129
    # High mask (Slaves 17..31): 18A is bit 1 (18-17=1) -> 1<<1 = 2
    assert master.reg_table.read_word("%R643") == 2


def test_master_operational_phases() -> None:
    """Stage 4: Verify operational phase transitions and coil %M149."""
    master = ASiMasterEngine()
    assert master.phase == ASiMasterPhase.INITIALIZATION
    assert master.reg_table.read_bit("%M149") is False

    master.advance_phase(ASiMasterPhase.DETECTION_CONFIGURATION)
    assert master.phase == ASiMasterPhase.DETECTION_CONFIGURATION
    assert master.reg_table.read_bit("%M149") is False

    master.advance_phase(ASiMasterPhase.ACTIVATION)
    assert master.phase == ASiMasterPhase.ACTIVATION
    assert master.reg_table.read_bit("%M149") is False

    master.advance_phase(ASiMasterPhase.NORMAL_OPERATION)
    assert master.phase == ASiMasterPhase.NORMAL_OPERATION
    assert master.reg_table.read_bit("%M149") is True


def test_safety_at_work_dynamic_sequence() -> None:
    """Stage 5: Verify Safety at Work 8-step dynamic rolling sequence and trips."""
    mon = ASiSafetyAtWorkMonitor()
    t = 10.0

    # Normal sequence traversal
    for code in SAW_NOMINAL_SEQUENCE:
        t += 0.005
        assert mon.process_code_nibble(code, current_time=t) is True

    # Static zero trip
    assert mon.process_code_nibble(0x00, current_time=t + 0.005) is False
    assert mon.is_latched_trip is True
    assert mon.trip_reason == "ERR_SAW_STATIC_ZERO_CODE"

    # Reset
    mon.reset_safety()
    assert mon.is_latched_trip is False

    # Timeout trip
    mon.process_code_nibble(SAW_NOMINAL_SEQUENCE[0], current_time=t)
    assert mon.process_code_nibble(SAW_NOMINAL_SEQUENCE[1], current_time=t + 0.050) is False
    assert mon.trip_reason == "ERR_SAW_STEP_TIMEOUT"


def test_cyclic_split_phase_exchange() -> None:
    """Stage 6: Verify cyclic split phase polling across Bank A and Bank B."""
    master = ASiMasterEngine()
    s1a = ASiSlaveDescriptor(address=1, bank=ASiSlaveBank.BANK_A, di_nibble=0x1)
    s2a = ASiSlaveDescriptor(address=2, bank=ASiSlaveBank.BANK_A, di_nibble=0x2)
    s1b = ASiSlaveDescriptor(address=1, bank=ASiSlaveBank.BANK_B, di_nibble=0x3)

    master.add_configured_slave(s1a)
    master.add_configured_slave(s2a)
    master.add_configured_slave(s1b)
    master.advance_phase(ASiMasterPhase.NORMAL_OPERATION)

    r_a = master.execute_bus_cycle()
    assert r_a["split_phase"] == "BANK_A"
    assert r_a["successful_polls"] == 2

    r_b = master.execute_bus_cycle()
    assert r_b["split_phase"] == "BANK_B"
    assert r_b["successful_polls"] == 1


def test_bus_power_fail_apf() -> None:
    """Stage 7: Verify APF low-voltage detection and Horner register updates."""
    master = ASiMasterEngine()
    master.set_bus_power(False)
    assert (master.status_bits & ASiMasterStatusBits.POWER_SUPPLY_FAULT) != 0
    assert master.diagnostic_code == ASiDiagnosticCode.APF_LOW_VOLTAGE
    assert master.reg_table.read_uword("%R647") == int(ASiDiagnosticCode.APF_LOW_VOLTAGE)

    master.set_bus_power(True)
    assert (master.status_bits & ASiMasterStatusBits.POWER_SUPPLY_FAULT) == 0
    assert master.diagnostic_code == ASiDiagnosticCode.OK


def test_auto_addressing_engine() -> None:
    """Stage 8: Verify auto-addressing replacement from Address 0."""
    master = ASiMasterEngine()
    s5a = ASiSlaveDescriptor(address=5, bank=ASiSlaveBank.BANK_A, io_code=0x7, id_code=0x0)
    master.add_configured_slave(s5a)

    # Force 3 timeouts on 5A to trigger offline state
    for _ in range(3):
        master.simulate_slave_poll(s5a, force_timeout=True)
    master._sync_registers()

    assert "5A" in master.missing_slaves
    assert master.reg_table.read_bit("%M150") is True

    # Plug in matching replacement at address 0
    master.introduce_replacement_slave_at_zero(io_code=0x7, id_code=0x0)
    result = master.evaluate_auto_addressing()
    assert result == "AUTO_ADDRESSED_5A"
    assert len(master.missing_slaves) == 0
    assert s5a.is_online is True


def test_anti_ladder_guard() -> None:
    """Stage 9: Verify strict interception of ladder symbols with ERR_LADDER_FORBIDDEN."""
    bad_code = """
    PROGRAM ASiBadLadder
    VAR Flag : BOOL; END_VAR
    ---[ ]---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_code)
