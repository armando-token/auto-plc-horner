"""Unit Test Suite for Industrial AS-Interface (AS-i v3.0 / IEC 62026-2) Protocol Engine & Safety at Work Supervisor.

Work Package: W136 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R970..%R977, %M226..%M227).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Master-slave polling, A/B extended addressing (up to 62 slaves), and APM Manchester encoding.
4. Section 4: Safety at Work (SaW) dynamic 8x4-bit safety code table sequence generation and validation.
5. Section 5: SaW safety monitor response time (< 40ms) and dual redundant channel discrepancy detection.
6. Section 6: Process safety trips (0xA101, 0xA102, 0xA103, 0xA104) and Horner coil assertion (%M226, %M227).
7. Section 7: Horner OCS register space synchronization (%R970..%R977, %M226..%M227).
8. Section 8: 9-stage verification suite integration test writing evidence JSON.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest
import time
from typing import Any, Dict

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.as_interface import (
    ASI_APM_NOISE_THRESHOLD_V,
    ASI_APM_PULSE_VOLTAGE_V,
    ASI_BAUD_RATE_HZ,
    ASI_BIT_TIME_US,
    ASI_CABLE_NOMINAL_VOLTAGE_V,
    ASI_DISCREPANCY_TIMEOUT_S,
    ASI_EXTENDED_CYCLE_TIME_MS,
    ASI_MAX_BANK_A_SLAVES,
    ASI_MAX_BANK_B_SLAVES,
    ASI_MAX_CABLE_LENGTH_M,
    ASI_MAX_EXTENDED_SLAVES,
    ASI_MAX_SLAVES,
    ASI_MAX_STANDARD_SLAVES,
    ASI_NETWORK_SYNC_PURE_ST_POU,
    ASI_PULSE_TIME_US,
    ASI_PURE_ST_POU,
    ASI_REQUEST_BITS,
    ASI_RESPONSE_BITS,
    ASI_SAFETY_SYNC_PURE_ST_POU,
    ASI_SAW_DEFAULT_DISCREPANCY_TIMEOUT_S,
    ASI_SAW_MAX_REACTION_TIME_S,
    ASI_SAW_MAX_RESPONSE_TIME_MS,
    ASI_STANDARD_CYCLE_TIME_MS,
    ASI_TRANSACTION_BITS,
    ASI_TRANSACTION_TIME_US,
    SAW_ESTOP_SEQUENCE,
    SAW_GATE_INTERLOCK_SEQUENCE,
    SAW_GENERIC_SEQUENCE,
    SAW_LIGHT_CURTAIN_SEQUENCE,
    SAW_NOMINAL_SEQUENCE,
    ASInterfaceCommandType,
    ASInterfaceDiagnosticCode,
    ASInterfaceError,
    ASInterfaceMasterEngine,
    ASInterfacePhase,
    ASInterfaceRequestFrame,
    ASInterfaceResponseFrame,
    ASInterfaceSafeChannelStatusBits,
    ASInterfaceSafetyDevice,
    ASInterfaceSafetyDeviceType,
    ASInterfaceSafetyMonitor,
    ASInterfaceSlaveBank,
    ASInterfaceSlaveDescriptor,
    ASInterfaceStatusBits,
    AsiCommandType,
    AsiDiagnosticCode,
    AsiFramingError,
    AsiMaster,
    AsiMasterPhase,
    AsiMasterRequestFrame,
    AsiSafeChannelStatusBits,
    AsiSafetyDevice,
    AsiSafetyDeviceType,
    AsiSafetyMonitor,
    AsiSlaveBank,
    AsiSlaveDescriptor,
    AsiSlaveResponseFrame,
    AsiStatusBits,
    DiscrepancyTimeoutError,
    DualChannelDiscrepancyDetector,
    FrameFormatError,
    ManchesterAPMSimulator,
    SafetyAtWorkTripError,
    SequenceDesyncError,
    SlaveAddressingError,
    SlaveCapacityExceededError,
    calc_cycle_time_ms,
    calc_transaction_time_us,
    calculate_cycle_time_us,
    calculate_transaction_time_us,
    compute_master_request_pb,
    compute_request_pb,
    compute_response_pb,
    compute_slave_response_pb,
    decode_apm_manchester,
    encode_apm_manchester,
    generate_safety_code_sequence,
    generate_saw_code_table,
    run_as_interface_verification,
    scale_process_input_to_int16,
    verify_as_interface_pure_st,
    verify_asi_safety_pure_st,
    verify_saw_code_sequence,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def asi_master(register_table: RegisterTable) -> AsiMaster:
    """Provides a fresh AsiMaster initialized with register table."""
    return AsiMaster(register_table=register_table)


@pytest.fixture
def safety_monitor() -> AsiSafetyMonitor:
    """Provides a fresh AsiSafetyMonitor initialized with nominal sequence."""
    return AsiSafetyMonitor()


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================


class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Pure ST POU compliance, AST verification, and register bindings (%R970..%R977, %M226..%M227)."""

    def test_verify_as_interface_pure_st_function(self) -> None:
        """Verify the built-in pure ST validation helpers return True."""
        assert verify_as_interface_pure_st() is True
        assert verify_asi_safety_pure_st() is True

    def test_pure_st_safety_sync_pou_ast_parsing(self) -> None:
        """Parse ASI_SAFETY_SYNC_PURE_ST_POU (AsiSafetySync) and assert AST attributes."""
        SecurityGuard.assert_pure_st_content(ASI_SAFETY_SYNC_PURE_ST_POU)
        res = STParser.validate_code(ASI_SAFETY_SYNC_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        parser = STParser()
        ast = parser.parse_pou(ASI_SAFETY_SYNC_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "AsiSafetySync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R970", "%R971", "%R972", "%R973",
            "%R974", "%R975", "%R976", "%R977",
            "%M226", "%M227",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        expected_vars = {
            "StatusWord",
            "SafetyCodeSequenceWord",
            "CycleCounter",
            "PrimaryProcessInputScaled",
            "SecondaryProcessInputScaled",
            "TelegramErrorCounter",
            "SafeChannelStatusWord",
            "DiagnosticStatusCode",
            "AsiMasterActive",
            "AsiSafetyAtWorkTrip",
            "SafetyCodeTripFault",
            "ChannelDiscrepancyTripFault",
            "SlaveOfflineFault",
            "ApmNoiseFault",
        }
        assert expected_vars.issubset(var_names)

    def test_pure_st_network_sync_pou_ast_parsing(self) -> None:
        """Parse ASI_NETWORK_SYNC_PURE_ST_POU (AsiNetworkSync) and assert AST attributes."""
        SecurityGuard.assert_pure_st_content(ASI_NETWORK_SYNC_PURE_ST_POU)
        res = STParser.validate_code(ASI_NETWORK_SYNC_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        parser = STParser()
        ast = parser.parse_pou(ASI_NETWORK_SYNC_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "AsiNetworkSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R970", "%R971", "%R972", "%R973",
            "%R974", "%R975", "%R976", "%R977",
            "%M226", "%M227",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

        var_names = {v.name for v in ast.variables}
        assert "ActiveSlaveCount" in var_names
        assert "AsiMasterActive" in var_names
        assert "AsiSafetyAtWorkTrip" in var_names

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify pure ST POUs pass SecurityGuard pure ST assertion cleanly."""
        SecurityGuard.assert_pure_st_content(ASI_SAFETY_SYNC_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(ASI_NETWORK_SYNC_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(ASI_PURE_ST_POU)


# ============================================================================
# Section 2: Anti-Ladder Security Guard Asserting LadderForbiddenError
# ============================================================================


class TestSection2AntiLadderSecurity:
    """Tests for SecurityGuard strict rejection of ladder logic constructs."""

    @pytest.mark.parametrize(
        "sample",
        [
            "PROGRAM BadContacts\nVAR Flag: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM",
            "PROGRAM BadNegative\nVAR Flag: BOOL; END_VAR\n---[/]---\nEND_PROGRAM",
            "PROGRAM BadRung\nVAR Flag: BOOL; END_VAR\nRUNG 1: XIC %M226 OTE %M227 END_RUNG\nEND_PROGRAM",
            "PROGRAM BadCoil\nVAR Out: BOOL; END_VAR\n---(S)---\nEND_PROGRAM",
            "PROGRAM BadReset\nVAR Out: BOOL; END_VAR\n---(R)---\nEND_PROGRAM",
            "PROGRAM BadMnemonic\nVAR Out: BOOL; END_VAR\nXIO %M226\nEND_PROGRAM",
            "PROGRAM BadLatch\nVAR Out: BOOL; END_VAR\nOTL %M227\nEND_PROGRAM",
            "PROGRAM BadUnlatch\nVAR Out: BOOL; END_VAR\nOTU %M227\nEND_PROGRAM",
            "PROGRAM BadNetwork\nVAR X: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, sample: str) -> None:
        """Verify embedded ladder constructs raise LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(sample)

        res = STParser.validate_code(sample)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 3: Master-Slave Polling, A/B Extended Addressing, & APM Manchester
# ============================================================================


class TestSection3MasterSlavePollingAddressingAndAPM:
    """Tests for master-slave polling, A/B extended addressing (up to 62 slaves), and APM Manchester modulation."""

    def test_timing_constants_and_analytical_formulas(self) -> None:
        """Verify AS-Interface analytical timing constants and formulas."""
        assert math.isclose(ASI_BAUD_RATE_HZ, 166666.67, abs_tol=0.1)
        assert math.isclose(ASI_BIT_TIME_US, 6.0, abs_tol=1e-6)
        assert math.isclose(ASI_PULSE_TIME_US, 2.0, abs_tol=1e-6)
        assert ASI_REQUEST_BITS == 14
        assert ASI_RESPONSE_BITS == 7
        assert ASI_TRANSACTION_BITS == 26
        assert math.isclose(ASI_TRANSACTION_TIME_US, 156.0, abs_tol=1e-6)

        tx_time = calc_transaction_time_us()
        assert math.isclose(tx_time, 156.0, abs_tol=1e-6)
        assert math.isclose(calculate_transaction_time_us(), 156.0, abs_tol=1e-6)

        # 31 standard slaves + 2 management slots = 33 * 156.0 us = 5148.0 us (~5.0 ms)
        c_time_31 = calculate_cycle_time_us(31)
        assert math.isclose(c_time_31, 5148.0, abs_tol=1e-6)
        assert calc_cycle_time_ms(31) == 5.0

        # 62 extended A/B slaves + 2 management slots = 64 * 156.0 us = 9984.0 us (~10.0 ms)
        c_time_62 = calculate_cycle_time_us(62)
        assert math.isclose(c_time_62, 9984.0, abs_tol=1e-6)
        assert calc_cycle_time_ms(62, is_extended_ab=True) == 10.0

    def test_master_request_frame_encoding_and_decoding(self) -> None:
        """Encode, compute parity, and decode 14-bit master request frame."""
        req = AsiMasterRequestFrame(
            command=AsiCommandType.DATA_EXCHANGE,
            address=14,
            info=0x0B,
            cb=0,
        )
        raw = req.encode_raw_word()
        assert 0 <= raw <= 0x3FFF

        # Validate even parity
        expected_pb = compute_master_request_pb(req.sb, req.cb, req.address, req.info)
        assert req.pb == expected_pb
        assert compute_request_pb(req.sb, req.cb, req.address, req.info) == expected_pb

        # Decode
        decoded, err = AsiMasterRequestFrame.decode_raw_word(raw)
        assert err == "OK"
        assert decoded is not None
        assert decoded.address == 14
        assert decoded.info == 0x0B
        assert decoded.cb == 0

    def test_slave_response_frame_encoding_and_decoding(self) -> None:
        """Encode, compute parity, and decode 7-bit slave response frame."""
        resp = AsiSlaveResponseFrame(info=0x0D)
        raw = resp.encode_raw_word()
        assert 0 <= raw <= 0x7F

        expected_pb = compute_slave_response_pb(resp.sb, resp.info)
        assert resp.pb == expected_pb
        assert compute_response_pb(resp.sb, resp.info) == expected_pb

        decoded, err = AsiSlaveResponseFrame.decode_raw_word(raw)
        assert err == "OK"
        assert decoded is not None
        assert decoded.info == 0x0D

    def test_framing_error_detection(self) -> None:
        """Verify detection of start bit, end bit, parity corruption, and length overflow."""
        req = AsiMasterRequestFrame(command=AsiCommandType.READ_STATUS, address=7, info=0x1E, cb=1)
        raw = req.encode_raw_word()

        # Corrupt parity
        corrupted_pb = raw ^ 0b00000000000010
        _, err_p = AsiMasterRequestFrame.decode_raw_word(corrupted_pb)
        assert err_p == "ERR_PARITY"

        # Corrupt start bit
        corrupted_sb = raw | (1 << 13)
        _, err_sb = AsiMasterRequestFrame.decode_raw_word(corrupted_sb)
        assert err_sb == "ERR_START_BIT"

        # Corrupt end bit
        corrupted_eb = raw & ~1
        _, err_eb = AsiMasterRequestFrame.decode_raw_word(corrupted_eb)
        assert err_eb == "ERR_END_BIT"

        # Length overflow
        _, err_len = AsiMasterRequestFrame.decode_raw_word(0x4000)
        assert err_len == "ERR_FRAME_LENGTH"

    def test_manchester_apm_physical_layer_simulation(self) -> None:
        """Verify Alternating Pulse Modulation (APM) pulse waveform, bit timing, and noise thresholds."""
        apm = ManchesterAPMSimulator(
            nominal_voltage_v=ASI_CABLE_NOMINAL_VOLTAGE_V,
            pulse_amplitude_v=ASI_APM_PULSE_VOLTAGE_V,
            cable_length_m=50.0,
        )
        assert apm.nominal_voltage_v == 30.0
        assert apm.pulse_amplitude_v == 2.5

        # Transmit 14-bit pattern with alternating bits
        samples = apm.simulate_pulse_train(0x2AAA, bit_count=14)
        assert len(samples) > 20

        voltages = [s[1] for s in samples]
        assert max(voltages) > 30.0
        assert min(voltages) < 30.0

        # Timing verification
        assert apm.verify_apm_bit_timing(6.0, tolerance_pct=0.03) is True
        assert apm.verify_apm_bit_timing(6.15, tolerance_pct=0.03) is True
        assert apm.verify_apm_bit_timing(6.25, tolerance_pct=0.03) is False

        # Noise limits
        ok, _ = apm.check_physical_layer_integrity(noise_v=0.5, jitter_us=0.1)
        assert ok is True
        fail_noise, err = apm.check_physical_layer_integrity(noise_v=1.5)
        assert fail_noise is False
        assert err == "ERR_APM_NOISE_EXCESSIVE"

    def test_apm_manchester_encode_decode_roundtrip(self) -> None:
        """Verify standalone APM Manchester pulse encoding and recovery."""
        req = AsiMasterRequestFrame(command=AsiCommandType.DATA_EXCHANGE, address=19, info=0x0E, cb=0)
        word = req.encode_raw_word()
        pulses = encode_apm_manchester(word, ASI_REQUEST_BITS)
        assert len(pulses) == 28

        recovered = decode_apm_manchester(pulses)
        assert recovered == word

        # Frame method
        assert req.encode_apm_pulses() == pulses

        # Response frame
        resp = AsiSlaveResponseFrame(info=0x0B)
        resp_word = resp.encode_raw_word()
        resp_pulses = resp.encode_apm_pulses()
        assert len(resp_pulses) == 14
        assert decode_apm_manchester(resp_pulses) == resp_word

    def test_extended_ab_addressing_capacity_up_to_62_slaves(self) -> None:
        """Verify support for up to 31 standard slaves and 62 extended A/B slaves."""
        assert ASI_MAX_SLAVES == 62
        assert ASI_MAX_STANDARD_SLAVES == 31
        assert ASI_MAX_EXTENDED_SLAVES == 62
        assert ASI_MAX_BANK_A_SLAVES == 31
        assert ASI_MAX_BANK_B_SLAVES == 31

        # Standard master: 31 slaves
        master_std = AsiMaster(is_extended_ab=False)
        for i in range(1, 32):
            master_std.register_slave(AsiSlaveDescriptor(address=i, bank=AsiSlaveBank.STANDARD))
        assert master_std.active_slave_count == 31
        assert master_std.cycle_time_ms == 5.0

        # Extended master: 62 slaves
        master_ext = AsiMaster(is_extended_ab=True)
        for i in range(1, 32):
            master_ext.register_slave(AsiSlaveDescriptor(address=i, bank=AsiSlaveBank.BANK_A))
            master_ext.register_slave(AsiSlaveDescriptor(address=i, bank=AsiSlaveBank.BANK_B))
        assert master_ext.active_slave_count == 62
        assert master_ext.cycle_time_ms == 10.0
        assert bool(master_ext.status_bits & AsiStatusBits.EXTENDED_AB_MODE)

    def test_split_phase_polling_alternation(self, asi_master: AsiMaster) -> None:
        """Verify split-phase polling alternates between Bank A and Bank B."""
        m = asi_master
        m.register_slave(AsiSlaveDescriptor(address=1, bank=AsiSlaveBank.BANK_A))
        m.register_slave(AsiSlaveDescriptor(address=1, bank=AsiSlaveBank.BANK_B))
        m.advance_phase(AsiMasterPhase.NORMAL_OPERATION)

        r1 = m.step_scan_cycle()
        r2 = m.step_scan_cycle()
        r3 = m.step_scan_cycle()

        assert r1["split_phase"] != r2["split_phase"]
        assert r2["split_phase"] != r3["split_phase"]
        assert r1["split_phase"] == r3["split_phase"]
        assert m.cycle_counter == 3


# ============================================================================
# Section 4: Safety at Work (SaW) Dynamic 8x4-Bit Safety Code Table Sequence
# ============================================================================


class TestSection4SafetyAtWorkCodeSequence:
    """Tests for SaW 8x4-bit dynamic code table generation, verification, and sequence tracking."""

    def test_nominal_safety_sequences_attributes(self) -> None:
        """Verify nominal sequence length, non-zero nibbles, and distinct profiles."""
        assert len(SAW_NOMINAL_SEQUENCE) == 8
        assert len(SAW_ESTOP_SEQUENCE) == 8
        assert len(SAW_LIGHT_CURTAIN_SEQUENCE) == 8
        assert len(SAW_GATE_INTERLOCK_SEQUENCE) == 8
        assert len(SAW_GENERIC_SEQUENCE) == 8

        for seq in (SAW_ESTOP_SEQUENCE, SAW_LIGHT_CURTAIN_SEQUENCE, SAW_GATE_INTERLOCK_SEQUENCE, SAW_GENERIC_SEQUENCE):
            assert all(0 < n < 0x0F for n in seq)
            assert verify_saw_code_sequence(seq) is True

        assert SAW_ESTOP_SEQUENCE != SAW_LIGHT_CURTAIN_SEQUENCE
        assert SAW_ESTOP_SEQUENCE != SAW_GATE_INTERLOCK_SEQUENCE

    def test_generate_safety_code_sequence_and_saw_table(self) -> None:
        """Verify dynamic code table generator produces valid deterministic sequences."""
        seq_default = generate_safety_code_sequence(AsiSafetyDeviceType.ESTOP)
        assert seq_default == SAW_ESTOP_SEQUENCE

        seq_rot = generate_safety_code_sequence(AsiSafetyDeviceType.ESTOP, seed=2)
        assert len(seq_rot) == 8
        assert seq_rot != seq_default
        assert verify_saw_code_sequence(seq_rot) is True

        table_alias = generate_saw_code_table(AsiSafetyDeviceType.LIGHT_CURTAIN)
        assert table_alias == SAW_LIGHT_CURTAIN_SEQUENCE

    def test_verify_saw_code_sequence_rejection_rules(self) -> None:
        """Verify code sequence validator rejects short, zero-containing, or repeating tables."""
        assert verify_saw_code_sequence((0x0E, 0x0B, 0x07)) is False
        assert verify_saw_code_sequence((0x0E, 0x00, 0x07, 0x0D, 0x09, 0x06, 0x03, 0x05)) is False
        assert verify_saw_code_sequence((0x0E, 0x0E, 0x07, 0x0D, 0x09, 0x06, 0x03, 0x05)) is False

    def test_safety_device_dynamic_code_progression_and_wrap(self) -> None:
        """Verify safety device steps through dynamic sequence and wraps around."""
        dev = AsiSafetyDevice(device_id=1, address=1, device_type=AsiSafetyDeviceType.ESTOP)
        nibbles = [dev.get_next_dynamic_nibble() for _ in range(8)]
        assert tuple(nibbles) == SAW_ESTOP_SEQUENCE

        # Rollover to step 0
        wrap_nibble = dev.get_next_dynamic_nibble()
        assert wrap_nibble == SAW_ESTOP_SEQUENCE[0]

    def test_static_zero_e_stop_trip(self, safety_monitor: AsiSafetyMonitor) -> None:
        """Verify static zero code (0x00) causes immediate fail-safe trip."""
        mon = safety_monitor
        ok, trip = mon.evaluate_code_nibble(0x00)
        assert ok is False
        assert trip == "ERR_SAW_STATIC_ZERO_CODE"
        assert mon.is_latched_trip is True

    def test_corrupted_code_mismatch_trip(self, safety_monitor: AsiSafetyMonitor) -> None:
        """Verify code mismatch against expected sequence trips monitor."""
        mon = safety_monitor
        ok, trip = mon.evaluate_code_nibble(0x01)  # expected 0x0E
        assert ok is False
        assert "ERR_SAW_CODE_MISMATCH" in str(trip)
        assert mon.is_latched_trip is True

    def test_frozen_code_trip(self, safety_monitor: AsiSafetyMonitor) -> None:
        """Verify repeated identical non-zero code trips monitor."""
        mon = safety_monitor
        mon.evaluate_code_nibble(0x0E)
        # Repeat 0x0E instead of advancing to 0x0B
        ok, trip = mon.evaluate_code_nibble(0x0E)
        assert ok is False
        assert trip == "ERR_SAW_FROZEN_CODE"
        assert mon.is_latched_trip is True

    def test_latched_trip_requires_manual_reset(self, safety_monitor: AsiSafetyMonitor) -> None:
        """Verify latched trip blocks subsequent valid codes until reset_safety() is called."""
        mon = safety_monitor
        mon.evaluate_code_nibble(0x00)
        assert mon.is_latched_trip is True

        # Rejected while latched
        ok, _ = mon.evaluate_code_nibble(0x0E)
        assert ok is False

        # Reset clears latch
        mon.reset_safety()
        assert mon.is_latched_trip is False
        assert mon.current_expected_step == 0


# ============================================================================
# Section 5: SaW Safety Monitor Response Time (< 40ms) & Discrepancy Detection
# ============================================================================


class TestSection5SafetyResponseTimeAndDiscrepancy:
    """Tests for SaW response time (< 40ms) enforcement and dual redundant channel discrepancy."""

    def test_response_time_and_discrepancy_constants(self) -> None:
        """Verify SaW maximum response time (< 40 ms) and discrepancy threshold constants."""
        assert ASI_SAW_MAX_REACTION_TIME_S == 0.040
        assert ASI_SAW_MAX_RESPONSE_TIME_MS == 40.0
        assert ASI_DISCREPANCY_TIMEOUT_S == 0.100
        assert ASI_SAW_DEFAULT_DISCREPANCY_TIMEOUT_S == 0.100

    def test_saw_monitor_timeout_trip_exceeding_40ms(self) -> None:
        """Verify sequence update delayed beyond 40ms triggers fail-safe trip."""
        mon = AsiSafetyMonitor(expected_sequence=SAW_ESTOP_SEQUENCE, max_reaction_time_s=0.040)
        t0 = time.time()
        mon.evaluate_code_nibble(SAW_ESTOP_SEQUENCE[0], current_time=t0)

        # Advance by 45ms (> 40ms threshold)
        ok, trip = mon.evaluate_code_nibble(SAW_ESTOP_SEQUENCE[1], current_time=t0 + 0.045)
        assert ok is False
        assert trip == "ERR_SAW_STREAM_TIMEOUT"
        assert mon.is_latched_trip is True

    def test_saw_healthy_update_within_response_time(self, safety_monitor: AsiSafetyMonitor) -> None:
        """Verify updates at 5ms, 10ms, and 20ms pass without timeout."""
        mon = safety_monitor
        t = 100.0
        for i in range(4):
            ok, trip = mon.evaluate_code_nibble(SAW_ESTOP_SEQUENCE[i], current_time=t)
            assert ok is True
            assert trip is None
            t += 0.010
        assert mon.consecutive_valid_codes == 4
        assert mon.is_latched_trip is False

    def test_dual_channel_discrepancy_synchronized(self) -> None:
        """Verify synchronized redundant channels (Ch1=True, Ch2=True) remain healthy."""
        dev = AsiSafetyDevice(device_id=1, address=1, discrepancy_timeout_s=0.100)
        dev.set_channels(ch1=True, ch2=True)
        tripped = dev.update_discrepancy(dt_s=0.050)
        assert tripped is False
        assert dev.discrepancy_active is False
        assert dev.discrepancy_tripped is False

    def test_transient_discrepancy_tolerated_within_window(self) -> None:
        """Verify transient discrepancy persisting for 50ms (<= 100ms) clears without trip."""
        dev = AsiSafetyDevice(device_id=1, address=1, discrepancy_timeout_s=0.100)
        dev.set_channels(ch1=False, ch2=True)  # Discrepancy begins
        dev.update_discrepancy(dt_s=0.050)     # 50ms elapsed
        assert dev.discrepancy_active is True
        assert dev.discrepancy_tripped is False

        # Re-align contacts
        dev.set_channels(ch1=True, ch2=True)
        dev.update_discrepancy(dt_s=0.010)
        assert dev.discrepancy_active is False
        assert dev.discrepancy_tripped is False
        assert dev.discrepancy_timer_s == 0.0

    def test_discrepancy_timeout_trips_permanently(self) -> None:
        """Verify discrepancy persisting > 100ms triggers permanent safety trip."""
        dev = AsiSafetyDevice(device_id=1, address=1, discrepancy_timeout_s=0.100)
        dev.set_channels(ch1=False, ch2=True)
        dev.update_discrepancy(dt_s=0.060)  # 60ms
        assert dev.discrepancy_tripped is False

        dev.update_discrepancy(dt_s=0.050)  # Total 110ms > 100ms
        assert dev.discrepancy_tripped is True
        assert dev.is_tripped is True

    def test_standalone_dual_channel_discrepancy_detector(self) -> None:
        """Verify DualChannelDiscrepancyDetector class evaluation and reset."""
        detector = DualChannelDiscrepancyDetector(discrepancy_timeout_s=0.050)
        t = 50.0

        # Synchronized
        ok, reason = detector.evaluate(True, True, current_time=t)
        assert ok is True
        assert reason is None

        # Discrepancy starts
        ok, reason = detector.evaluate(True, False, current_time=t + 0.010)
        assert ok is True
        assert detector.is_in_discrepancy is True

        # Discrepancy timeout exceeded (60ms elapsed > 50ms)
        ok, reason = detector.evaluate(True, False, current_time=t + 0.070)
        assert ok is False
        assert "ERR_SAW_CHANNEL_DISCREPANCY" in str(reason)
        assert detector.is_tripped is True

        detector.reset()
        assert detector.is_tripped is False


# ============================================================================
# Section 6: Process Safety Trips (0xA101..0xA104) & Horner Coils (%M226, %M227)
# ============================================================================


class TestSection6ProcessSafetyTrips:
    """Tests for safety trips 0xA101..0xA104 asserting %M226/%M227 and diagnostic codes."""

    def test_diagnostic_code_values(self) -> None:
        """Verify diagnostic enumeration values match Work Package W136 specification."""
        assert int(AsiDiagnosticCode.OK) == 0x0000
        assert int(AsiDiagnosticCode.ASI_ERR_SAFETY_CODE_TRIP) == 0xA101
        assert int(AsiDiagnosticCode.ASI_ERR_CHANNEL_DISCREPANCY) == 0xA102
        assert int(AsiDiagnosticCode.ASI_ERR_SLAVE_OFFLINE) == 0xA103
        assert int(AsiDiagnosticCode.ASI_ERR_APM_NOISE_FAULT) == 0xA104

        assert int(ASInterfaceDiagnosticCode.ASI_ERR_SAFETY_CODE_TRIP) == 0xA101
        assert int(ASInterfaceDiagnosticCode.ASI_ERR_CHANNEL_DISCREPANCY) == 0xA102
        assert int(ASInterfaceDiagnosticCode.ASI_ERR_SLAVE_OFFLINE) == 0xA103
        assert int(ASInterfaceDiagnosticCode.ASI_ERR_APM_NOISE_FAULT) == 0xA104

    def test_trip_0xa101_safety_code(self, asi_master: AsiMaster) -> None:
        """0xA101 clears %M226 and asserts %M227."""
        m = asi_master
        assert m.reg_table.read_bit("%M226") is True
        assert m.reg_table.read_bit("%M227") is False

        m.trigger_safety_trip(AsiDiagnosticCode.ASI_ERR_SAFETY_CODE_TRIP)
        assert m.reg_table.read_bit("%M227") is True
        assert m.reg_table.read_bit("%M226") is False
        assert m.reg_table.read_uword("%R977") == 0xA101
        assert bool(m.status_bits & AsiStatusBits.SAFETY_TRIP) is True

    def test_trip_0xa102_channel_discrepancy(self, asi_master: AsiMaster) -> None:
        """0xA102 asserts %M227 and sets diagnostic code."""
        m = asi_master
        m.trigger_safety_trip(AsiDiagnosticCode.ASI_ERR_CHANNEL_DISCREPANCY)
        assert m.reg_table.read_bit("%M227") is True
        assert m.reg_table.read_uword("%R977") == 0xA102

    def test_trip_0xa103_slave_offline(self, asi_master: AsiMaster) -> None:
        """0xA103 triggered when projected slave drops offline."""
        m = asi_master
        slave = AsiSlaveDescriptor(address=3)
        m.register_slave(slave)

        # Drop slave with 3 consecutive timeouts
        for _ in range(3):
            m.poll_slave(slave, force_timeout=True)
        m.step_scan_cycle()

        assert m.reg_table.read_uword("%R977") == 0xA103
        assert bool(m.status_bits & AsiStatusBits.SLAVE_OFFLINE) is True

    def test_trip_0xa104_apm_power_fault(self, asi_master: AsiMaster) -> None:
        """0xA104 triggered on APM line power fail."""
        m = asi_master
        m.set_bus_power(power_ok=False)
        assert m.reg_table.read_uword("%R977") == 0xA104
        assert m.reg_table.read_bit("%M226") is False

        # Restore power
        m.set_bus_power(power_ok=True)
        assert m.reg_table.read_uword("%R977") == 0x0000
        assert m.reg_table.read_bit("%M226") is True

    def test_reset_safety_recovery(self, asi_master: AsiMaster) -> None:
        """Verify reset_safety clears alarms and restores healthy coils %M226=True, %M227=False."""
        m = asi_master
        m.trigger_safety_trip(AsiDiagnosticCode.ASI_ERR_SAFETY_CODE_TRIP)
        assert m.reg_table.read_bit("%M227") is True

        m.reset_safety()
        assert m.diagnostic_code == AsiDiagnosticCode.OK
        assert m.reg_table.read_uword("%R977") == 0x0000
        assert m.reg_table.read_bit("%M226") is True
        assert m.reg_table.read_bit("%M227") is False


# ============================================================================
# Section 7: Horner OCS Register Space Synchronization (%R970..%R977)
# ============================================================================


class TestSection7HornerOCSMemoryIntegration:
    """Tests for Horner OCS register space synchronization (%R970..%R977, %M226..%M227)."""

    def test_register_synchronization_after_scan_cycle(self, asi_master: AsiMaster) -> None:
        """Verify registers %R970..%R977 after a healthy scan cycle."""
        m = asi_master
        dev = AsiSafetyDevice(device_id=1, address=1, device_type=AsiSafetyDeviceType.ESTOP)
        m.register_slave(AsiSlaveDescriptor(address=1, is_safety_slave=True, safety_device=dev))
        m.advance_phase(AsiMasterPhase.NORMAL_OPERATION)
        m.step_scan_cycle(pv_val=45.6, sv_val=12.3)

        rt = m.reg_table
        r970 = rt.read_uword("%R970")
        r971 = rt.read_uword("%R971")
        r972 = rt.read_uword("%R972")
        r973 = rt.read_word("%R973")
        r974 = rt.read_word("%R974")
        r975 = rt.read_uword("%R975")
        r976 = rt.read_uword("%R976")
        r977 = rt.read_uword("%R977")
        m226 = rt.read_bit("%M226")
        m227 = rt.read_bit("%M227")

        assert bool(r970 & AsiStatusBits.MASTER_ACTIVE)
        assert (r970 >> 8) & 0x7F == 1  # 1 active slave
        assert r972 == 1                # CycleCounter = 1
        assert r973 == 456              # 45.6 * 10
        assert r974 == 123              # 12.3 * 10
        assert r975 == 0                # 0 errors
        assert r977 == 0x0000           # OK
        assert m226 is True             # Active
        assert m227 is False            # No trip

    def test_process_input_scaling_and_clamping(self) -> None:
        """Verify scaling helper function bounds and clamping to INT16 range."""
        assert scale_process_input_to_int16(45.6) == 456
        assert scale_process_input_to_int16(-12.3) == -123
        assert scale_process_input_to_int16(5000.0) == 32767   # Clamped max
        assert scale_process_input_to_int16(-5000.0) == -32768  # Clamped min

    def test_auto_addressing_engine_register_sync(self, asi_master: AsiMaster) -> None:
        """Verify auto-addressing replacement from Address 0 updates registers and clears fault."""
        m = asi_master
        slave = AsiSlaveDescriptor(address=5, io_code=0x7, id_code=0x0)
        m.register_slave(slave)

        # Force slave offline
        for _ in range(3):
            m.poll_slave(slave, force_timeout=True)
        m.step_scan_cycle()

        assert "5" in m.missing_slaves
        assert bool(m.status_bits & AsiStatusBits.SLAVE_OFFLINE)

        # Plug in replacement at Address 0
        m.introduce_replacement_slave_at_zero(io_code=0x7, id_code=0x0)
        result = m.evaluate_auto_addressing()
        assert result == "AUTO_ADDRESSED_5"
        assert len(m.missing_slaves) == 0
        assert slave.is_online is True

        m.step_scan_cycle()
        assert m.reg_table.read_uword("%R977") == 0x0000
        assert m.reg_table.read_bit("%M226") is True


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration & Evidence Persistence
# ============================================================================


class TestSection8VerificationSuiteIntegration:
    """Tests for the complete 9-stage verification suite and evidence persistence."""

    def test_run_as_interface_verification_success(self) -> None:
        """Verify the 9-stage verification returns a clean SUCCESS status."""
        result = run_as_interface_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9
        for t in result["data"]["tests"]:
            assert t["passed"] is True

    def test_run_as_interface_verification_writes_evidence(self, tmp_path: Path) -> None:
        """Verify verification writes valid JSON evidence matching contract schema."""
        evidence_file = tmp_path / "as_interface_evidence.json"
        result = run_as_interface_verification(evidence_path=str(evidence_file))

        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W136"
        assert data["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
        assert "Industrial AS-Interface" in data["data"]["component"]
        assert data["data"]["checks_passed"] == 9
        assert len(data["data"]["tests"]) == 9
        assert data["data"]["register_map"]["status_word_active_slave_count"] == "%R970"
        assert data["data"]["register_map"]["safety_code_sequence_word"] == "%R971"
        assert data["data"]["register_map"]["cycle_counter"] == "%R972"
        assert data["data"]["register_map"]["primary_process_input_scaled"] == "%R973"
        assert data["data"]["register_map"]["secondary_process_input_scaled"] == "%R974"
        assert data["data"]["register_map"]["telegram_error_counter"] == "%R975"
        assert data["data"]["register_map"]["safe_channel_status_word"] == "%R976"
        assert data["data"]["register_map"]["diagnostic_status_code"] == "%R977"
        assert data["data"]["register_map"]["asi_master_active"] == "%M226"
        assert data["data"]["register_map"]["asi_safety_at_work_trip"] == "%M227"

    def test_evidence_metrics_schema(self) -> None:
        """Verify evidence metrics dictionary has all expected fields."""
        result = run_as_interface_verification()
        metrics = result["data"]["metrics"]
        assert metrics["max_standard_slaves"] == 31
        assert metrics["max_extended_slaves"] == 62
        assert math.isclose(metrics["baud_rate_hz"], 166666.67, abs_tol=0.1)
        assert metrics["saw_max_reaction_time_s"] <= 0.040
        assert metrics["bit_time_us"] == 6.0
        assert metrics["transaction_time_us"] == 156.0
        assert metrics["standard_cycle_time_ms"] == 5.0
        assert metrics["extended_cycle_time_ms"] == 10.0
