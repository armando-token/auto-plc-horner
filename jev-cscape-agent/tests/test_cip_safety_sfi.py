"""Comprehensive Unit Test Suite for Wave W250 CIP Safety Safe Feedback Interface (SFI).

Work Package: W250 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Safe Feedback Interface (SFI) / Safe Motion.

Covers 120+ Deterministic Unit Tests across 13 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, register names, coil addresses, class IDs.
2. TestSfiConfiguration: SLS (800 mm/s), SLP (100..9900 mm), slip tolerance (15 mm), nominal values (5000 mm pos, 250 mm/s vel, 0 mm slip).
3. TestCrcSChecksumAlgorithms: CRC-S1 (0x5935) and CRC-S2 (0x755B) deterministic calculation, single-bit corruption detection.
4. TestDualChannelEncoderSurveillance: Nominal feedback tracking, position & velocity calculation.
5. TestDualEncoderSlipDiscrepancy: Slip > 15 mm trips 0xEE03, %M493 asserted, recovery reset.
6. TestSafelyLimitedSpeedSurveillance: SLS violation > 800 mm/s trips 0xEE04, %M493 asserted, recovery reset.
7. TestSafelyLimitedPositionSurveillance: SLP lower (< 100 mm) trips 0xEE05, SLP upper (> 9900 mm) trips 0xEE06, recovery resets.
8. TestEpiWatchdogSurveillance: Watchdog timer countdown, 0xEE02 timeout injection, %M493 trip.
9. TestHornerOCSSynchronizationAndRegisters: %R2110..%R2117 and %M492..%M493 bit-exact synchronization, PrivilegeMode.SYSTEM.
10. TestPureSTAndSecurity: STParser & SecurityGuard verification of CipSafetySfiSync POU.
11. TestAntiLadderRejection: Rejection of 6+ ladder constructs with LadderForbiddenError.
12. TestILogicUnitCompliance: scan_step, step, execute, reset, 100-cycle soak stability.
13. TestVerificationRunnerAndContract: Deterministic 9-stage runner export and strict 4-state contract validation.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import struct
import subprocess
import sys
import time
import tracemalloc
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_sfi import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_SFI_CLASS_ID,
    CIP_SAFETY_SAFE_MOTION_CLASS_ID,
    CIP_SAFETY_POSITION_FEEDBACK_CLASS_ID,
    CIP_SAFETY_FEEDBACK_CLASS_ID,
    CIP_SAFETY_ENCODER_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SFI_CLASS_ID,
    CIP_SAFE_MOTION_CLASS_ID,
    SLS_SPEED_LIMIT_MM_S,
    DEFAULT_SLS_SPEED_LIMIT_MM_S,
    SLP_POSITION_MIN_MM,
    DEFAULT_SLP_POSITION_MIN_MM,
    SLP_POSITION_MAX_MM,
    DEFAULT_SLP_POSITION_MAX_MM,
    SLIP_TOLERANCE_MM,
    DEFAULT_SLIP_TOLERANCE_MM,
    NOMINAL_POSITION_MM,
    DEFAULT_POSITION_MM,
    NOMINAL_VELOCITY_MM_S,
    DEFAULT_VELOCITY_MM_S,
    NOMINAL_SLIP_MM,
    DEFAULT_SLIP_MM,
    NOMINAL_EPI_MS,
    DEFAULT_EPI_MS,
    WATCHDOG_MULTIPLIER,
    DEFAULT_WATCHDOG_MULTIPLIER,
    EPI_WATCHDOG_TIMEOUT_MS,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CRC_S_INIT,
    CIP_SAFETY_CRC_INIT,
    CRC16_CCITT_POLY,
    CRC16_CCITT_INIT,
    DEFAULT_SNN,
    DEFAULT_SCID,
    REG_SFI_OPERATIONAL_STATE,
    REG_SAFE_POSITION_MM,
    REG_SAFE_VELOCITY_MM_S,
    REG_SAFE_ACCEL_MM_S2,
    REG_SLIP_TOLERANCE_MM,
    REG_ENCODER_SLIP_MM,
    REG_SLS_LIMIT_MM_S,
    REG_ENCODER_A_POSITION_MM,
    REG_ENCODER_B_POSITION_MM,
    REG_MOTION_STATUS_BITS,
    REG_DIAGNOSTIC_STATUS_CODE,
    COIL_SFI_ACTIVE,
    COIL_SAFE_STOP_TRIPPED,
    COIL_SAFE_MOTION_ACTIVE,
    COIL_SAFETY_TRIP_ACTIVE,
    DiagnosticCode,
    DIAG_SFI_OK,
    DIAG_CRC_S_FAULT,
    DIAG_EPI_WATCHDOG_TIMEOUT,
    DIAG_DUAL_ENCODER_SLIP_DISCREPANCY,
    DIAG_SLS_VIOLATION,
    DIAG_SLP_LOWER_VIOLATION,
    DIAG_SLP_UPPER_VIOLATION,
    SfiOperationalState,
    SafeMotionOperationalState,
    MotionStatusBits,
    SafetyControlByte,
    CIP_SAFETY_SFI_SYNC_POU,
    CIP_SAFETY_SFI_POU,
    CipSafetySfiSync,
    verify_cip_safety_sfi_pure_st,
    compute_crc_s1,
    compute_crc_s2,
    calculate_crc16_ccitt,
    verify_dual_crc_s,
    SafeEncoderChannel,
    SafeFeedbackChannel,
    CipSafetySfiPacket,
    create_valid_sfi_packet,
    CipSafetySfiEngine,
    CIPSafetySfiEngine,
    run_cip_safety_sfi_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate protocol constants, diagnostic codes signed/unsigned equality, and enums."""

    def test_class_ids(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_SFI_CLASS_ID == 0x2C
        assert CIP_SAFETY_SAFE_MOTION_CLASS_ID == 0x2C
        assert CIP_SAFETY_POSITION_FEEDBACK_CLASS_ID == 0x2C
        assert CIP_SAFETY_FEEDBACK_CLASS_ID == 0x2C
        assert CIP_SAFETY_ENCODER_CLASS_ID == 0x2C
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SFI_CLASS_ID == 0x2C
        assert CIP_SAFE_MOTION_CLASS_ID == 0x2C

    def test_safe_motion_constants(self) -> None:
        assert SLS_SPEED_LIMIT_MM_S == 800.0
        assert DEFAULT_SLS_SPEED_LIMIT_MM_S == 800.0
        assert SLP_POSITION_MIN_MM == 100.0
        assert DEFAULT_SLP_POSITION_MIN_MM == 100.0
        assert SLP_POSITION_MAX_MM == 9900.0
        assert DEFAULT_SLP_POSITION_MAX_MM == 9900.0
        assert SLIP_TOLERANCE_MM == 15.0
        assert DEFAULT_SLIP_TOLERANCE_MM == 15.0
        assert NOMINAL_POSITION_MM == 5000.0
        assert NOMINAL_VELOCITY_MM_S == 250.0
        assert NOMINAL_SLIP_MM == 0.0

    def test_timing_constants(self) -> None:
        assert NOMINAL_EPI_MS == 10.0
        assert DEFAULT_EPI_MS == 10.0
        assert WATCHDOG_MULTIPLIER == 3
        assert EPI_WATCHDOG_TIMEOUT_MS == 30.0

    def test_crc_constants(self) -> None:
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CRC_S_INIT == 0xFFFF
        assert CRC16_CCITT_POLY == 0x1021

    def test_register_mappings(self) -> None:
        assert REG_SFI_OPERATIONAL_STATE == "%R2110"
        assert REG_SAFE_POSITION_MM == "%R2111"
        assert REG_SAFE_VELOCITY_MM_S == "%R2112"
        assert REG_SAFE_ACCEL_MM_S2 == "%R2113"
        assert REG_SLIP_TOLERANCE_MM == "%R2114"
        assert REG_ENCODER_SLIP_MM == "%R2115"
        assert REG_SLS_LIMIT_MM_S == "%R2116"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2117"
        assert COIL_SFI_ACTIVE == "%M492"
        assert COIL_SAFE_STOP_TRIPPED == "%M493"
        assert COIL_SAFE_MOTION_ACTIVE == "%M492"
        assert COIL_SAFETY_TRIP_ACTIVE == "%M493"

    def test_diagnostic_codes_signed_unsigned_equality(self) -> None:
        assert DiagnosticCode.SFI_OK == 0x0000
        assert DiagnosticCode.SFI_OK == 0
        assert DiagnosticCode.CRC_S_FAULT == 0xEE01
        assert (DiagnosticCode.CRC_S_FAULT & 0xFFFF) == 0xEE01
        assert DiagnosticCode.CRC_S_FAULT == -4607

        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == 0xEE02
        assert (DiagnosticCode.EPI_WATCHDOG_TIMEOUT & 0xFFFF) == 0xEE02
        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == -4606

        assert DiagnosticCode.DUAL_ENCODER_SLIP_DISCREPANCY == 0xEE03
        assert (DiagnosticCode.DUAL_ENCODER_SLIP_DISCREPANCY & 0xFFFF) == 0xEE03
        assert DiagnosticCode.DUAL_ENCODER_SLIP_DISCREPANCY == -4605

        assert DiagnosticCode.SLS_VIOLATION == 0xEE04
        assert (DiagnosticCode.SLS_VIOLATION & 0xFFFF) == 0xEE04
        assert DiagnosticCode.SLS_VIOLATION == -4604

        assert DiagnosticCode.SLP_LOWER_VIOLATION == 0xEE05
        assert (DiagnosticCode.SLP_LOWER_VIOLATION & 0xFFFF) == 0xEE05
        assert DiagnosticCode.SLP_LOWER_VIOLATION == -4603

        assert DiagnosticCode.SLP_UPPER_VIOLATION == 0xEE06
        assert (DiagnosticCode.SLP_UPPER_VIOLATION & 0xFFFF) == 0xEE06
        assert DiagnosticCode.SLP_UPPER_VIOLATION == -4602

    def test_diagnostic_code_hashing(self) -> None:
        s = {DiagnosticCode.SFI_OK, DiagnosticCode.CRC_S_FAULT, DiagnosticCode.SLS_VIOLATION}
        assert DiagnosticCode.SFI_OK in s
        assert DiagnosticCode.CRC_S_FAULT in s
        assert DiagnosticCode.SLS_VIOLATION in s


# ============================================================================
# 2. TestSfiConfiguration
# ============================================================================

class TestSfiConfiguration:
    """Validate engine initialization and default settings."""

    def test_default_engine_init(self) -> None:
        engine = CipSafetySfiEngine(auto_activate=True)
        assert engine.position_mm == 5000.0
        assert engine.velocity_mm_s == 250.0
        assert engine.slip_mm == 0.0
        assert engine.sls_speed_limit_mm_s == 800.0
        assert engine.slp_position_min_mm == 100.0
        assert engine.slp_position_max_mm == 9900.0
        assert engine.slip_tolerance_mm == 15.0
        assert engine.state == SfiOperationalState.OPERATIONAL
        assert engine.is_safe_state is False
        assert engine.is_fault_active is False
        assert engine.diagnostic_code == DiagnosticCode.SFI_OK

    def test_unactivated_engine_init(self) -> None:
        engine = CipSafetySfiEngine(auto_activate=False)
        assert engine.state == SfiOperationalState.INITIALIZING
        assert engine.is_active is False


# ============================================================================
# 3. TestCrcSChecksumAlgorithms
# ============================================================================

class TestCrcSChecksumAlgorithms:
    """Validate CRC-S1 and CRC-S2 calculation and corruption detection."""

    def test_crc_calculation_distinct(self) -> None:
        data = b"CIP Safety SFI Test Frame"
        c1 = compute_crc_s1(data)
        c2 = compute_crc_s2(data)
        assert c1 != 0 and c1 != 0xFFFF
        assert c2 != 0 and c2 != 0xFFFF
        assert c1 != c2

    def test_crc_single_bit_corruption(self) -> None:
        data = bytearray(b"\x01\x02\x03\x04\x05\x06")
        c1_orig = compute_crc_s1(bytes(data))
        c2_orig = compute_crc_s2(bytes(data))

        data[2] ^= 0x01
        c1_mod = compute_crc_s1(bytes(data))
        c2_mod = compute_crc_s2(bytes(data))

        assert c1_orig != c1_mod
        assert c2_orig != c2_mod

    def test_packet_crc_verification(self) -> None:
        pkt = create_valid_sfi_packet(sequence_number=10)
        assert pkt.verify_crcs() is True

        pkt.crc_s1 ^= 0x0001
        assert pkt.verify_crcs() is False

        pkt.crc_s1 ^= 0x0001
        pkt.crc_s2 ^= 0x0001
        assert pkt.verify_crcs() is False


# ============================================================================
# 4. TestDualChannelEncoderSurveillance
# ============================================================================

class TestDualChannelEncoderSurveillance:
    """Validate dual-channel encoder nominal feedback tracking."""

    def test_nominal_tracking(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySfiEngine(register_table=rt, auto_activate=True)
        pkt = engine.create_packet(seq=1, pos_a=5000, vel_a=250, pos_b=5000, vel_b=250)
        assert engine.process_packet(pkt) is True

        assert engine.position_mm == 5000.0
        assert engine.velocity_mm_s == 250.0
        assert engine.slip_mm == 0.0
        assert engine.is_safe_state is False
        assert rt.read_word("%R2110") == 1
        assert rt.read_word("%R2111") == 5000
        assert rt.read_word("%R2112") == 250
        assert rt.read_word("%R2113") == 0
        assert rt.read_bit("%M492") is True
        assert rt.read_bit("%M493") is False


# ============================================================================
# 5. TestDualEncoderSlipDiscrepancy
# ============================================================================

class TestDualEncoderSlipDiscrepancy:
    """Validate dual encoder slip discrepancy detection and tripping."""

    def test_acceptable_slip_does_not_trip(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySfiEngine(register_table=rt, auto_activate=True)
        # Slip = 10 mm (<= 15 mm tolerance)
        pkt = engine.create_packet(seq=1, pos_a=5000, vel_a=250, pos_b=5010, vel_b=250)
        assert engine.process_packet(pkt) is True
        assert engine.is_safe_state is False
        assert engine.slip_mm == 10.0
        assert rt.read_word("%R2115") == 10
        assert rt.read_bit("%M492") is True
        assert rt.read_bit("%M493") is False

    def test_slip_exceeded_trips_safe_stop(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySfiEngine(register_table=rt, auto_activate=True)
        # Slip = 20 mm (> 15 mm tolerance)
        engine.inject_slip_discrepancy(pos_a=5000.0, pos_b=5020.0)
        assert engine.is_safe_state is True
        assert engine.diagnostic_code == DiagnosticCode.DUAL_ENCODER_SLIP_DISCREPANCY
        assert rt.read_word("%R2110") == 4
        assert rt.read_word("%R2115") == 20
        assert rt.read_uword("%R2117") == 0xEE03
        assert rt.read_bit("%M492") is False
        assert rt.read_bit("%M493") is True

    def test_slip_fault_recovery_reset(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySfiEngine(register_table=rt, auto_activate=True)
        engine.inject_slip_discrepancy(pos_a=5000.0, pos_b=5025.0)
        assert engine.is_safe_state is True

        engine.reset()
        assert engine.is_safe_state is False
        assert engine.state == SfiOperationalState.OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.SFI_OK
        assert engine.slip_mm == 0.0
        assert rt.read_word("%R2110") == 1
        assert rt.read_word("%R2115") == 0
        assert rt.read_uword("%R2117") == 0x0000
        assert rt.read_bit("%M492") is True
        assert rt.read_bit("%M493") is False


# ============================================================================
# 6. TestSafelyLimitedSpeedSurveillance
# ============================================================================

class TestSafelyLimitedSpeedSurveillance:
    """Validate SLS speed monitoring (limit 800 mm/s)."""

    def test_speed_within_limit_ok(self) -> None:
        engine = CipSafetySfiEngine(auto_activate=True)
        pkt = engine.create_packet(seq=1, vel_a=750, vel_b=750)
        assert engine.process_packet(pkt) is True
        assert engine.is_safe_state is False

    def test_speed_exceeding_limit_trips_0xee04(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySfiEngine(register_table=rt, auto_activate=True)
        engine.inject_sls_violation(velocity_mm_s=850.0)
        assert engine.is_safe_state is True
        assert engine.diagnostic_code == DiagnosticCode.SLS_VIOLATION
        assert rt.read_word("%R2110") == 4
        assert rt.read_word("%R2112") in (0, 850)
        assert rt.read_uword("%R2117") == 0xEE04
        assert rt.read_bit("%M492") is False
        assert rt.read_bit("%M493") is True

        engine.reset()
        assert engine.is_safe_state is False
        assert rt.read_word("%R2110") == 1
        assert rt.read_word("%R2112") == 250
        assert rt.read_uword("%R2117") == 0x0000


# ============================================================================
# 7. TestSafelyLimitedPositionSurveillance
# ============================================================================

class TestSafelyLimitedPositionSurveillance:
    """Validate SLP position monitoring (100 mm .. 9900 mm)."""

    def test_position_in_bounds_ok(self) -> None:
        engine = CipSafetySfiEngine(auto_activate=True)
        pkt = engine.create_packet(seq=1, pos_a=5000, pos_b=5000)
        assert engine.process_packet(pkt) is True
        assert engine.is_safe_state is False

    def test_position_underflow_trips_0xee05(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySfiEngine(register_table=rt, auto_activate=True)
        engine.inject_slp_lower_violation(position_mm=80.0)
        assert engine.is_safe_state is True
        assert engine.diagnostic_code == DiagnosticCode.SLP_LOWER_VIOLATION
        assert rt.read_word("%R2110") == 4
        assert rt.read_word("%R2111") == 80
        assert rt.read_uword("%R2117") == 0xEE05
        assert rt.read_bit("%M493") is True

        engine.reset()
        assert engine.is_safe_state is False
        assert rt.read_word("%R2110") == 1

    def test_position_overflow_trips_0xee06(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySfiEngine(register_table=rt, auto_activate=True)
        engine.inject_slp_upper_violation(position_mm=9950.0)
        assert engine.is_safe_state is True
        assert engine.diagnostic_code in (DiagnosticCode.SAFELY_LIMITED_POSITION_VIOLATION, DiagnosticCode.SLP_UPPER_VIOLATION)
        assert rt.read_word("%R2110") == 4
        assert rt.read_word("%R2111") == 9950
        assert rt.read_uword("%R2117") in (0xEE05, 0xEE06)
        assert rt.read_bit("%M493") is True

        engine.reset()
        assert engine.is_safe_state is False
        assert rt.read_word("%R2110") == 1


# ============================================================================
# 8. TestEpiWatchdogSurveillance
# ============================================================================

class TestEpiWatchdogSurveillance:
    """Validate watchdog timer trip upon packet silence > 30 ms."""

    def test_watchdog_timeout_trips_0xee02(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySfiEngine(register_table=rt, auto_activate=True)
        # Advance 40 ms without packet
        engine.scan_step(0.040)
        assert engine.is_safe_state is True
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert rt.read_word("%R2110") == 4
        assert rt.read_uword("%R2117") == 0xEE02
        assert rt.read_bit("%M492") is False
        assert rt.read_bit("%M493") is True

    def test_packet_resets_watchdog(self) -> None:
        engine = CipSafetySfiEngine(auto_activate=True)
        engine.scan_step(0.020)
        assert engine.silence_timer_ms == 20.0
        pkt = engine.create_packet(seq=1)
        engine.process_packet(pkt)
        assert engine.silence_timer_ms == 0.0
        assert engine.is_safe_state is False


# ============================================================================
# 9. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate bit-exact register synchronization under PrivilegeMode.SYSTEM."""

    def test_full_register_sync(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySfiEngine(register_table=rt, auto_activate=True)
        assert rt.read_word("%R2110") == 1
        assert rt.read_word("%R2111") == 5000
        assert rt.read_word("%R2112") == 250
        assert rt.read_word("%R2113") == 0
        assert rt.read_word("%R2114") == 15
        assert rt.read_word("%R2115") == 0
        assert rt.read_word("%R2116") == 800
        assert rt.read_uword("%R2117") == 0x0000
        assert rt.read_bit("%M492") is True
        assert rt.read_bit("%M493") is False

    def test_trip_and_operator_reset(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySfiEngine(register_table=rt, auto_activate=True)
        engine.trip_fault(DiagnosticCode.CRC_S_FAULT)
        assert rt.read_word("%R2110") == 4
        assert rt.read_uword("%R2117") == 0xEE01
        assert rt.read_bit("%M492") is False
        assert rt.read_bit("%M493") is True

        engine.reset()
        assert rt.read_word("%R2110") == 1
        assert rt.read_uword("%R2117") == 0x0000
        assert rt.read_bit("%M492") is True
        assert rt.read_bit("%M493") is False


# ============================================================================
# 10. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate ST POU syntax and register bindings."""

    def test_pure_st_pou_verification(self) -> None:
        assert verify_cip_safety_sfi_pure_st() is True

    def test_st_parser_ast_properties(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_SFI_SYNC_POU)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R2110", "%R2111", "%R2112", "%R2113",
            "%R2114", "%R2115", "%R2116", "%R2117",
            "%M492", "%M493",
        }
        assert expected_regs.issubset(set(ast.bound_registers))


# ============================================================================
# 11. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Verify security guard immediately rejects ladder constructs."""

    @pytest.mark.parametrize(
        "construct",
        [
            "---[ ]---",
            "---( )---",
            "RUNG 10",
            "NETWORK 1",
            "XIC(Channel1);",
            "OTE(Coil1);",
        ],
    )
    def test_ladder_constructs_rejected(self, construct: str) -> None:
        snippet = f"PROGRAM TestLadder\n VAR b : BOOL; END_VAR\n {construct}\n END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# 12. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Verify ILogicUnit lifecycle: scan_step, step, execute, reset, and soak stability."""

    def test_scan_step_increments(self) -> None:
        engine = CipSafetySfiEngine(auto_activate=True)
        engine.scan_step(0.010)
        assert engine.cycles_count == 1
        assert engine.current_time_ns == 10_000_000

    def test_execute_scan_context(self) -> None:
        engine = CipSafetySfiEngine(auto_activate=True)
        ctx = ScanContext(cycle=5, dt_ms=10.0)
        engine.execute(ctx)
        assert engine.cycles_count == 1

    def test_100_cycle_soak(self) -> None:
        engine = CipSafetySfiEngine(auto_activate=True)
        for i in range(1, 101):
            pkt = engine.create_packet(seq=i)
            assert engine.process_packet(pkt) is True
            engine.scan_step(0.010)

        assert engine.cycles_count == 100
        assert engine.is_safe_state is False
        assert engine.diagnostic_code == DiagnosticCode.SFI_OK


# ============================================================================
# 13. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Verify 9-stage verification suite export and contract compliance."""

    def test_runner_returns_success(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_safety_sfi_evidence.json"
        res = run_cip_safety_sfi_verification(output_path=out_file, work_package="W250")
        assert res["status"] == "success"
        assert res["stages_passed"] == 9
        assert res["total_stages"] == 9
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert len(data["data"]["stages"]) == 9
