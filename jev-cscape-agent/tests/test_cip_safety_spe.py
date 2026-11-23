"""Comprehensive Unit Test Suite for Wave W265 CIP Safety Over Single Pair Ethernet (10BASE-T1L) Protocol Engine.

Work Package: W265 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Single Pair Ethernet (SPE IEEE 802.3cg 10BASE-T1L / IEC 61784-3-2) for Horner OCS.

Covers Comprehensive Deterministic Unit Tests across 12 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit values, string representations,
   bitwise operations, hashing, enums, register names, coil addresses, and class IDs.
2. TestDualCrcAndFrameIntegrity: CRC-S1 (0x5935), CRC-S2 (0x755B), dual CRC verification, diversified sequence
   counters (~seq & 0xFFFF), frame serialization, and single-bit mutation corruption detection.
3. TestStateTransitions: Progression across SafeSPEState (IDLE -> PHY_TRAINING -> LINK_UP_UNSAFE -> SAFE_OPERATIONAL -> SAFE_STOP_TRIPPED),
   property setters, and recovery resets.
4. TestPhyTrainingLossTrip: 10BASE-T1L PHY training loss trip (0xEE51 SPE_PHY_TRAINING_LOSS), open-circuit / short
   loop resistance detection (<= 0 or > 25,000 mOhm), coil %M528 assertion, register reflection, and recovery reset.
5. TestSnrDegradationTrip: 10BASE-T1L SNR margin surveillance, nominal tracking (24.5 dB -> 245), threshold surveillance
   (< 6.0 dB -> 60 tenth dB trips 0xEE52 SPE_SNR_DEGRADATION_TRIP), coil %M528 assertion, register reflection, and recovery reset.
6. TestSafetyCrcFaultTrip: Safety frame dual-CRC corruption detection, inverted sequence mismatch detection, SNN mismatch detection
   (0xEE53 SPE_SAFETY_CRC_FAULT), Rx CRC error counter (%R2265) increment, coil %M528 assertion, and recovery reset.
7. TestEpiTimeoutTrip: Expected Packet Interval watchdog surveillance, nominal tracking (2500 us), timeout trip
   (>= 7500 us -> 0xEE54 SPE_EPI_TIMEOUT_TRIP), watchdog feeding, scan cycle integration, coil %M528 assertion, and recovery reset.
8. TestRegisterSynchronization: %R2260..%R2267 and %M527..%M528 bit-exact synchronization, PrivilegeMode.SYSTEM,
   auto-sync property setters, safe write wrappers (safe_write_word, safe_write_uword, safe_write_bit).
9. TestPureSTAndSecurity: STParser & SecurityGuard verification of CipSafetySpeSync POU, AST variable memory_address
   and bound registers validation.
10. TestAntiLadderConstructRejection: Rejection of ladder logic constructs (contacts, coils, rungs, networks, mnemonics)
    with LadderForbiddenError.
11. TestILogicUnitComplianceAndSoak: ILogicUnit interface compliance (scan_step, step, execute, reset),
    properties validation, 100-cycle continuous soak simulation, and heap boundedness (< 100 KB growth).
12. TestExceptionsAndVerificationRunner: Exception inheritance hierarchy, 10-stage runner execution,
    strict 4-state contract validation, and evidence emission.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import tracemalloc
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_spe import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_SPE_CLASS_ID,
    CIP_SAFETY_10BASE_T1L_CLASS_ID,
    NOMINAL_CIP_SAFETY_SPE_LINK_STATE,
    DEFAULT_LINK_STATE,
    NOMINAL_CIP_SAFETY_SPE_LOOP_RESISTANCE_MILLIOHM,
    DEFAULT_LOOP_RESISTANCE_MILLIOHM,
    DEFAULT_LOOP_RESISTANCE,
    MIN_LOOP_RESISTANCE_MILLIOHM,
    MAX_LOOP_RESISTANCE_1000M_MILLIOHM,
    DEFAULT_MAX_LOOP_RESISTANCE_MILLIOHM,
    NOMINAL_CIP_SAFETY_SPE_SNR_MARGIN_TENTH_DB,
    DEFAULT_SNR_MARGIN_TENTH_DB,
    DEFAULT_SNR_MARGIN,
    MIN_SNR_MARGIN_TENTH_DB,
    MAX_SNR_MARGIN_TENTH_DB,
    DEFAULT_SNR_TRIP_THRESHOLD_TENTH_DB,
    SNR_MARGIN_WATCHDOG_LIMIT_TENTH_DB,
    NOMINAL_CIP_SAFETY_SPE_SAFETY_NETWORK_NUMBER,
    DEFAULT_SAFETY_NETWORK_NUMBER,
    DEFAULT_SNN,
    NOMINAL_CIP_SAFETY_SPE_TX_FRAME_COUNT,
    DEFAULT_TX_FRAME_COUNT,
    NOMINAL_CIP_SAFETY_SPE_RX_CRC_ERROR_COUNT,
    DEFAULT_RX_CRC_ERROR_COUNT,
    NOMINAL_CIP_SAFETY_SPE_EPI_TIMER_US,
    DEFAULT_EPI_TIMER_US,
    DEFAULT_EPI_US,
    MIN_EPI_TIMER_US,
    DEFAULT_EPI_TIMEOUT_THRESHOLD_US,
    MAX_EPI_WATCHDOG_LIMIT_US,
    NOMINAL_CIP_SAFETY_SPE_DIAGNOSTIC_CODE,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S_INIT,
    REG_CIP_SAFETY_SPE_LINK_STATE,
    REG_CIP_SAFETY_SPE_LOOP_RESISTANCE_MILLIOHM,
    REG_CIP_SAFETY_SPE_SNR_MARGIN_TENTH_DB,
    REG_CIP_SAFETY_SPE_SAFETY_NETWORK_NUMBER,
    REG_CIP_SAFETY_SPE_TX_FRAME_COUNT,
    REG_CIP_SAFETY_SPE_RX_CRC_ERROR_COUNT,
    REG_CIP_SAFETY_SPE_EPI_TIMER_US,
    REG_CIP_SAFETY_SPE_DIAGNOSTIC_CODE,
    COIL_CIP_SAFETY_SPE_OPERATIONAL,
    COIL_CIP_SAFETY_SPE_TRIPPED,
    REG_SPE_SAFETY_LINK_STATE,
    REG_SPE_LINK_STATE,
    REG_SPE_SAFETY_STATE,
    REG_SPE_STATE,
    REG_SPE_LOOP_RESISTANCE_MILLIOHM,
    REG_SPE_LOOP_RESISTANCE,
    REG_SPE_RESISTANCE_MILLIOHM,
    REG_SPE_SNR_MARGIN_TENTH_DB,
    REG_SPE_SNR_MARGIN,
    REG_SPE_SNR_DB,
    REG_SPE_SAFETY_NETWORK_NUMBER,
    REG_SPE_SNN,
    REG_SAFETY_NETWORK_NUMBER,
    REG_SPE_TX_FRAME_COUNT,
    REG_SPE_TX_COUNT,
    REG_SPE_TX_FRAMES,
    REG_SPE_RX_CRC_ERROR_COUNT,
    REG_SPE_RX_CRC_ERRORS,
    REG_SPE_CRC_ERROR_COUNT,
    REG_SPE_CRC_ERRORS,
    REG_SPE_EPI_TIMER_US,
    REG_SPE_EPI_TIMER,
    REG_SPE_EPI_US,
    REG_SPE_SAFETY_DIAGNOSTIC_CODE,
    REG_SPE_DIAGNOSTIC_CODE,
    REG_SPE_DIAG_CODE,
    REG_SAFETY_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_DIAGNOSTIC_CODE,
    COIL_SPE_OPERATIONAL,
    COIL_SPE_SAFETY_OPERATIONAL,
    COIL_SPE_LINK_HEALTHY,
    COIL_CIP_SAFETY_SPE_HEALTHY,
    COIL_SAFETY_OPERATIONAL,
    COIL_SAFETY_LINK_HEALTHY,
    COIL_SPE_TRIPPED,
    COIL_SPE_SAFETY_TRIPPED,
    COIL_SPE_SAFE_STOP_TRIPPED,
    COIL_CIP_SAFETY_SPE_STOP_TRIPPED,
    COIL_SAFETY_TRIPPED,
    COIL_SAFETY_STOP_TRIPPED,
    COIL_SAFE_STOP_TRIPPED,
    DiagnosticCode,
    DIAG_OK,
    DIAG_SPE_PHY_TRAINING_LOSS,
    DIAG_SPE_SNR_DEGRADATION_TRIP,
    DIAG_SPE_SAFETY_CRC_FAULT,
    DIAG_SPE_EPI_TIMEOUT_TRIP,
    DiagnosticStatusCode,
    SPEDiagnosticCode,
    CipSafetySpeDiagnosticCode,
    CIPSafetySPEDiagnosticCode,
    SafeSPEState,
    SPESafetyState,
    CIPSafetySPEState,
    CipSafetySpeState,
    SafeSpeState,
    CIPSafetySPEError,
    CIPSafetySPEPhyTrainingLossError,
    CIPSafetySPESnrDegradationError,
    CIPSafetySPECRCFaultError,
    CIPSafetySPEEpiTimeoutError,
    SPESafetyError,
    CipSafetySpeError,
    SPEPhyTrainingLossError,
    SPESnrDegradationError,
    SPECRCFaultError,
    SPEEpiTimeoutError,
    CIP_SAFETY_SPE_PURE_ST_POU,
    CIP_SAFETY_SPE_SYNC_POU,
    CIP_SAFETY_SPE_POU,
    PURE_ST_POU,
    CipSafetySpeSync,
    CipSafetySpeSyncPOU,
    verify_cip_safety_spe_pure_st,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    verify_dual_crc_s,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CIPSafetySPEFrame,
    CIPSafetySPEPacket,
    CipSafetySpeFrame,
    CipSafetySpePacket,
    SPESafetyFrame,
    SPESafetyPacket,
    create_valid_spe_safety_frame,
    create_valid_cip_safety_spe_frame,
    CIPSafetySPEEngine,
    CipSafetySpeEngine,
    CIPSafetySpeEngine,
    CIP_SAFETY_SPE_ENGINE,
    SPESafetyEngine,
    SpeSafetyEngine,
    CipSPESafetyEngine,
    CIPSPESafetyEngine,
    run_cip_safety_spe_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety Over SPE protocol constants, class IDs, enums, and diagnostic codes."""

    def test_class_ids_and_protocol_constants(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_SPE_CLASS_ID == 0x3D
        assert CIP_SAFETY_10BASE_T1L_CLASS_ID == 0x3D

        assert NOMINAL_CIP_SAFETY_SPE_LINK_STATE == 3
        assert DEFAULT_LINK_STATE == 3

        assert NOMINAL_CIP_SAFETY_SPE_LOOP_RESISTANCE_MILLIOHM == 1850
        assert DEFAULT_LOOP_RESISTANCE_MILLIOHM == 1850
        assert DEFAULT_LOOP_RESISTANCE == 1850
        assert MIN_LOOP_RESISTANCE_MILLIOHM == 1
        assert MAX_LOOP_RESISTANCE_1000M_MILLIOHM == 20000
        assert DEFAULT_MAX_LOOP_RESISTANCE_MILLIOHM == 25000

        assert NOMINAL_CIP_SAFETY_SPE_SNR_MARGIN_TENTH_DB == 245
        assert DEFAULT_SNR_MARGIN_TENTH_DB == 245
        assert DEFAULT_SNR_MARGIN == 245
        assert MIN_SNR_MARGIN_TENTH_DB == 0
        assert MAX_SNR_MARGIN_TENTH_DB == 400
        assert DEFAULT_SNR_TRIP_THRESHOLD_TENTH_DB == 60
        assert SNR_MARGIN_WATCHDOG_LIMIT_TENTH_DB == 60

        assert NOMINAL_CIP_SAFETY_SPE_SAFETY_NETWORK_NUMBER == 0x1A2B
        assert DEFAULT_SAFETY_NETWORK_NUMBER == 0x1A2B
        assert DEFAULT_SNN == 0x1A2B

        assert NOMINAL_CIP_SAFETY_SPE_TX_FRAME_COUNT == 100
        assert DEFAULT_TX_FRAME_COUNT == 100
        assert NOMINAL_CIP_SAFETY_SPE_RX_CRC_ERROR_COUNT == 0
        assert DEFAULT_RX_CRC_ERROR_COUNT == 0

        assert NOMINAL_CIP_SAFETY_SPE_EPI_TIMER_US == 2500
        assert DEFAULT_EPI_TIMER_US == 2500
        assert DEFAULT_EPI_US == 2500
        assert MIN_EPI_TIMER_US == 500
        assert DEFAULT_EPI_TIMEOUT_THRESHOLD_US == 7500
        assert MAX_EPI_WATCHDOG_LIMIT_US == 7500

        assert NOMINAL_CIP_SAFETY_SPE_DIAGNOSTIC_CODE == 0x0000

    def test_crc_polynomials_and_seeds(self) -> None:
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC_S_INIT == 0xFFFF

    def test_register_and_coil_addresses(self) -> None:
        assert REG_CIP_SAFETY_SPE_LINK_STATE == "%R2260"
        assert REG_CIP_SAFETY_SPE_LOOP_RESISTANCE_MILLIOHM == "%R2261"
        assert REG_CIP_SAFETY_SPE_SNR_MARGIN_TENTH_DB == "%R2262"
        assert REG_CIP_SAFETY_SPE_SAFETY_NETWORK_NUMBER == "%R2263"
        assert REG_CIP_SAFETY_SPE_TX_FRAME_COUNT == "%R2264"
        assert REG_CIP_SAFETY_SPE_RX_CRC_ERROR_COUNT == "%R2265"
        assert REG_CIP_SAFETY_SPE_EPI_TIMER_US == "%R2266"
        assert REG_CIP_SAFETY_SPE_DIAGNOSTIC_CODE == "%R2267"

        assert COIL_CIP_SAFETY_SPE_OPERATIONAL == "%M527"
        assert COIL_CIP_SAFETY_SPE_TRIPPED == "%M528"

        # Aliases
        assert REG_SPE_SAFETY_LINK_STATE == "%R2260"
        assert REG_SPE_LINK_STATE == "%R2260"
        assert REG_SPE_SAFETY_STATE == "%R2260"
        assert REG_SPE_STATE == "%R2260"

        assert REG_SPE_LOOP_RESISTANCE_MILLIOHM == "%R2261"
        assert REG_SPE_LOOP_RESISTANCE == "%R2261"
        assert REG_SPE_RESISTANCE_MILLIOHM == "%R2261"

        assert REG_SPE_SNR_MARGIN_TENTH_DB == "%R2262"
        assert REG_SPE_SNR_MARGIN == "%R2262"
        assert REG_SPE_SNR_DB == "%R2262"

        assert REG_SPE_SAFETY_NETWORK_NUMBER == "%R2263"
        assert REG_SPE_SNN == "%R2263"
        assert REG_SAFETY_NETWORK_NUMBER == "%R2263"

        assert REG_SPE_TX_FRAME_COUNT == "%R2264"
        assert REG_SPE_TX_COUNT == "%R2264"
        assert REG_SPE_TX_FRAMES == "%R2264"

        assert REG_SPE_RX_CRC_ERROR_COUNT == "%R2265"
        assert REG_SPE_RX_CRC_ERRORS == "%R2265"
        assert REG_SPE_CRC_ERROR_COUNT == "%R2265"
        assert REG_SPE_CRC_ERRORS == "%R2265"

        assert REG_SPE_EPI_TIMER_US == "%R2266"
        assert REG_SPE_EPI_TIMER == "%R2266"
        assert REG_SPE_EPI_US == "%R2266"

        assert REG_SPE_SAFETY_DIAGNOSTIC_CODE == "%R2267"
        assert REG_SPE_DIAGNOSTIC_CODE == "%R2267"
        assert REG_SPE_DIAG_CODE == "%R2267"
        assert REG_SAFETY_DIAGNOSTIC_CODE == "%R2267"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2267"
        assert REG_DIAGNOSTIC_CODE == "%R2267"

        assert COIL_SPE_OPERATIONAL == "%M527"
        assert COIL_SPE_SAFETY_OPERATIONAL == "%M527"
        assert COIL_SPE_LINK_HEALTHY == "%M527"
        assert COIL_CIP_SAFETY_SPE_HEALTHY == "%M527"
        assert COIL_SAFETY_OPERATIONAL == "%M527"
        assert COIL_SAFETY_LINK_HEALTHY == "%M527"

        assert COIL_SPE_TRIPPED == "%M528"
        assert COIL_SPE_SAFETY_TRIPPED == "%M528"
        assert COIL_SPE_SAFE_STOP_TRIPPED == "%M528"
        assert COIL_CIP_SAFETY_SPE_STOP_TRIPPED == "%M528"
        assert COIL_SAFETY_TRIPPED == "%M528"
        assert COIL_SAFETY_STOP_TRIPPED == "%M528"
        assert COIL_SAFE_STOP_TRIPPED == "%M528"

    def test_diagnostic_codes_values_and_representations(self) -> None:
        codes = [
            (DiagnosticCode.OK, 0x0000, 0, 0, "OK"),
            (DiagnosticCode.SPE_PHY_TRAINING_LOSS, 0xEE51, 61009, -4527, "SPE_PHY_TRAINING_LOSS"),
            (DiagnosticCode.SPE_SNR_DEGRADATION_TRIP, 0xEE52, 61010, -4526, "SPE_SNR_DEGRADATION_TRIP"),
            (DiagnosticCode.SPE_SAFETY_CRC_FAULT, 0xEE53, 61011, -4525, "SPE_SAFETY_CRC_FAULT"),
            (DiagnosticCode.SPE_EPI_TIMEOUT_TRIP, 0xEE54, 61012, -4524, "SPE_EPI_TIMEOUT_TRIP"),
        ]

        for obj, hex_val, u16_val, s16_val, name in codes:
            assert int(obj) == hex_val
            assert (int(obj) & 0xFFFF) == u16_val
            assert (u16_val - 0x10000 if u16_val >= 0x8000 else u16_val) == s16_val
            assert str(obj) == f"0x{hex_val:04X} ({name})"
            assert repr(obj) == f"DiagnosticCode.{name}(0x{hex_val:04X})"

            # Signed and unsigned equality
            assert obj == hex_val
            assert obj == u16_val
            assert obj == s16_val
            assert obj != (hex_val + 1)

    def test_diagnostic_code_bitwise_and_hashing(self) -> None:
        c1 = DiagnosticCode.SPE_PHY_TRAINING_LOSS  # 0xEE51
        c2 = DiagnosticCode.SPE_SNR_DEGRADATION_TRIP  # 0xEE52

        # Bitwise operations
        res_and = c1 & 0xFF00
        assert isinstance(res_and, DiagnosticCode)
        assert res_and == 0xEE00

        res_rand = 0x00FF & c1
        assert isinstance(res_rand, DiagnosticCode)
        assert res_rand == 0x0051

        # Hashing and sets
        code_set = {c1, c2, DiagnosticCode(0xEE51), DiagnosticCode(-4527)}
        assert len(code_set) == 2  # c1 and its duplicate collapsed
        assert c1 in code_set
        assert c2 in code_set
        assert DiagnosticCode(-4526) in code_set

        # Module-level aliases
        assert DIAG_OK is DiagnosticCode.OK
        assert DIAG_SPE_PHY_TRAINING_LOSS is DiagnosticCode.SPE_PHY_TRAINING_LOSS
        assert DIAG_SPE_SNR_DEGRADATION_TRIP is DiagnosticCode.SPE_SNR_DEGRADATION_TRIP
        assert DIAG_SPE_SAFETY_CRC_FAULT is DiagnosticCode.SPE_SAFETY_CRC_FAULT
        assert DIAG_SPE_EPI_TIMEOUT_TRIP is DiagnosticCode.SPE_EPI_TIMEOUT_TRIP
        assert DiagnosticStatusCode is DiagnosticCode
        assert SPEDiagnosticCode is DiagnosticCode
        assert CipSafetySpeDiagnosticCode is DiagnosticCode
        assert CIPSafetySPEDiagnosticCode is DiagnosticCode

    def test_diagnostic_code_properties_and_coercion(self) -> None:
        c = DiagnosticCode.SPE_PHY_TRAINING_LOSS
        assert c.value == 0xEE51
        assert int(c) == 0xEE51
        assert (c & 0xFFFF) == 0xEE51

        # Fallback comparison with non-int
        assert (c == "non_int_val") is False
        assert (c != "non_int_val") is True

        # Bitwise non-int
        with pytest.raises(TypeError):
            _ = c & "string"

    def test_crc_functions_variadic_args_and_errors(self) -> None:
        # Multiple byte chunks
        crc1 = compute_crc_s1(b"\x01\x02", b"\x03\x04")
        crc2 = compute_crc_s2(b"\x01\x02", b"\x03\x04")
        assert crc1 == compute_crc_s1(b"\x01\x02\x03\x04")
        assert crc2 == compute_crc_s2(b"\x01\x02\x03\x04")

        # Invalid arguments raise ValueError
        with pytest.raises(ValueError, match="Unsupported arguments to compute_crc_s1"):
            compute_crc_s1(12345)
        with pytest.raises(ValueError, match="Unsupported arguments to compute_crc_s2"):
            compute_crc_s2("invalid")

    def test_safety_state_enum_and_aliases(self) -> None:
        assert SafeSPEState.IDLE == 0
        assert SafeSPEState.PHY_TRAINING == 1
        assert SafeSPEState.LINK_UP_UNSAFE == 2
        assert SafeSPEState.SAFE_OPERATIONAL == 3
        assert SafeSPEState.SAFE_STOP_TRIPPED == 4

        # Camel-case aliases
        assert SafeSPEState.Idle == 0
        assert SafeSPEState.PhyTraining == 1
        assert SafeSPEState.LinkUpUnsafe == 2
        assert SafeSPEState.SafeOperational == 3
        assert SafeSPEState.SafeStopTripped == 4

        # Common aliases
        assert SafeSPEState.OPERATIONAL == 3
        assert SafeSPEState.SAFE_STOP == 4
        assert SafeSPEState.TRIPPED == 4

        # Type aliases
        assert SPESafetyState is SafeSPEState
        assert CIPSafetySPEState is SafeSPEState
        assert CipSafetySpeState is SafeSPEState
        assert SafeSpeState is SafeSPEState


# ============================================================================
# 2. TestDualCrcAndFrameIntegrity
# ============================================================================

class TestDualCrcAndFrameIntegrity:
    """Validate dual CRC-S1/S2 checksum computation, frame serialization, sequence inversion, and corruption detection."""

    def test_crc_s1_and_crc_s2_polynomials(self) -> None:
        sample_data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        crc1 = compute_crc_s1(sample_data)
        crc2 = compute_crc_s2(sample_data)

        assert isinstance(crc1, int)
        assert isinstance(crc2, int)
        assert 0 <= crc1 <= 0xFFFF
        assert 0 <= crc2 <= 0xFFFF
        assert crc1 != crc2

        # Aliases
        assert calc_crc_s1(sample_data) == crc1
        assert calc_crc_s2(sample_data) == crc2

    def test_frame_construction_and_serialization(self) -> None:
        frame = CIPSafetySPEFrame(
            sequence_primary=42,
            snn=0x1A2B,
            epi_timer_us=2500,
            loop_resistance_milliohm=1850,
            snr_margin_tenth_db=245,
            payload=b"\xCA\xFE\xBA\xBE",
        )

        assert frame.sequence_primary == 42
        assert frame.sequence_diversified == ((~42) & 0xFFFF)
        assert frame.verify_sequence() is True

        ser1 = frame.serialize_for_crc_s1()
        ser2 = frame.serialize_for_crc_s2()
        assert len(ser1) == 12 + len(frame.payload)
        assert len(ser2) == 12 + len(frame.payload)
        assert ser1 != ser2

    def test_calculate_and_verify_crcs(self) -> None:
        frame = CIPSafetySPEFrame(
            sequence_primary=100,
            snn=0x1A2B,
            payload=b"\x11\x22\x33\x44",
        )
        assert frame.crc_s1 == 0
        assert frame.crc_s2 == 0
        assert frame.verify_crcs() is False

        frame.calculate_crcs()
        assert frame.crc_s1 != 0
        assert frame.crc_s2 != 0
        assert frame.verify_crcs() is True
        assert verify_dual_crc_s(frame.serialize_for_crc_s1(), frame.serialize_for_crc_s2(), frame.crc_s1, frame.crc_s2) is True

    def test_single_bit_mutation_corruption_detection(self) -> None:
        frame = create_valid_spe_safety_frame(sequence_primary=77, payload=b"\xAA\xBB\xCC\xDD")
        assert frame.verify_crcs() is True

        frame.mutate_bit(byte_offset=0, bit_pos=0)
        assert frame.verify_crcs() is False

        # Restore bit
        frame.mutate_bit(byte_offset=0, bit_pos=0)
        assert frame.verify_crcs() is True

    def test_frame_aliases_and_factories(self) -> None:
        f1 = create_valid_spe_safety_frame(sequence_primary=5)
        f2 = create_valid_cip_safety_spe_frame(sequence_primary=5)

        assert isinstance(f1, CIPSafetySPEFrame)
        assert isinstance(f2, CIPSafetySPEFrame)
        assert f1.verify_crcs() is True
        assert f2.verify_crcs() is True

        assert CIPSafetySPEPacket is CIPSafetySPEFrame
        assert CipSafetySpeFrame is CIPSafetySPEFrame
        assert CipSafetySpePacket is CIPSafetySPEFrame
        assert SPESafetyFrame is CIPSafetySPEFrame
        assert SPESafetyPacket is CIPSafetySPEFrame


# ============================================================================
# 3. TestStateTransitions
# ============================================================================

class TestStateTransitions:
    """Validate SafeSPEState progression across IDLE -> PHY_TRAINING -> LINK_UP_UNSAFE -> SAFE_OPERATIONAL -> SAFE_STOP_TRIPPED."""

    def test_full_lifecycle_state_progression(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=False)

        # 0: IDLE
        assert engine.link_state == SafeSPEState.IDLE
        assert engine.operational is False
        assert engine.tripped is False
        assert engine.is_healthy is False
        assert rt.read_word("%R2260") == 0
        assert rt.read_bit("%M527") is False
        assert rt.read_bit("%M528") is False

        # 1: PHY_TRAINING
        engine.link_state = SafeSPEState.PHY_TRAINING
        assert engine.link_state == SafeSPEState.PHY_TRAINING
        assert engine.operational is False
        assert engine.tripped is False
        assert rt.read_word("%R2260") == 1
        assert rt.read_bit("%M527") is False

        # 2: LINK_UP_UNSAFE
        engine.link_state = SafeSPEState.LINK_UP_UNSAFE
        assert engine.link_state == SafeSPEState.LINK_UP_UNSAFE
        assert engine.operational is False
        assert engine.tripped is False
        assert rt.read_word("%R2260") == 2
        assert rt.read_bit("%M527") is False

        # 3: SAFE_OPERATIONAL
        engine.link_state = SafeSPEState.SAFE_OPERATIONAL
        assert engine.link_state == SafeSPEState.SAFE_OPERATIONAL
        assert engine.operational is True
        assert engine.tripped is False
        assert engine.is_healthy is True
        assert rt.read_word("%R2260") == 3
        assert rt.read_bit("%M527") is True
        assert rt.read_bit("%M528") is False

        # 4: SAFE_STOP_TRIPPED
        engine.link_state = SafeSPEState.SAFE_STOP_TRIPPED
        assert engine.link_state == SafeSPEState.SAFE_STOP_TRIPPED
        assert engine.operational is False
        assert engine.tripped is True
        assert engine.is_healthy is False
        assert rt.read_word("%R2260") == 4
        assert rt.read_bit("%M527") is False
        assert rt.read_bit("%M528") is True

    def test_state_aliases_and_setters(self) -> None:
        engine = CIPSafetySPEEngine(auto_activate=True)
        assert engine.state == SafeSPEState.SAFE_OPERATIONAL
        assert engine.safety_state == SafeSPEState.SAFE_OPERATIONAL

        engine.state = SafeSPEState.IDLE
        assert engine.link_state == SafeSPEState.IDLE

        engine.safety_state = SafeSPEState.PHY_TRAINING
        assert engine.link_state == SafeSPEState.PHY_TRAINING

    def test_engine_initial_state_and_tripped_init(self) -> None:
        # Test initial_state parameter
        e1 = CIPSafetySPEEngine(initial_state=SafeSPEState.LINK_UP_UNSAFE)
        assert e1.link_state == SafeSPEState.LINK_UP_UNSAFE

        # Test initial tripped state
        e2 = CIPSafetySPEEngine(link_state=SafeSPEState.SAFE_STOP_TRIPPED)
        assert e2.tripped is True
        assert e2.operational is False

        # Test initial non-zero diagnostic code
        e3 = CIPSafetySPEEngine(diagnostic_code=0xEE51)
        assert e3.tripped is True
        assert e3.operational is False

    def test_tripped_and_operational_setters(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        # Operational setter
        engine.operational = False
        assert engine.operational is False
        assert rt.read_bit("%M527") is False

        # Tripped setter
        engine.tripped = True
        assert engine.tripped is True
        assert engine.link_state == SafeSPEState.SAFE_STOP_TRIPPED
        assert engine.operational is False
        assert rt.read_bit("%M528") is True

    def test_aliases_properties(self) -> None:
        engine = CIPSafetySPEEngine(auto_activate=True)
        assert engine.link_healthy is True
        assert engine.safe_stop_tripped is False
        assert engine.cycle_count == 0

        engine.trip_phy_training_loss()
        assert engine.safe_stop_tripped is True
        assert engine.link_healthy is False

    def test_recovery_reset(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.trip_fault(DiagnosticCode.SPE_PHY_TRAINING_LOSS)
        assert engine.link_state == SafeSPEState.SAFE_STOP_TRIPPED
        assert engine.tripped is True
        assert engine.operational is False

        engine.reset()
        assert engine.link_state == SafeSPEState.SAFE_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.tripped is False
        assert engine.operational is True
        assert engine.is_healthy is True
        assert rt.read_word("%R2260") == 3
        assert rt.read_uword("%R2267") == 0x0000
        assert rt.read_bit("%M527") is True
        assert rt.read_bit("%M528") is False


# ============================================================================
# 4. TestPhyTrainingLossTrip
# ============================================================================

class TestPhyTrainingLossTrip:
    """Validate 10BASE-T1L PHY training loss trip (0xEE51) and coil %M528."""

    def test_manual_phy_training_loss_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.trip_phy_training_loss("PHY training failed or lost")
        assert engine.diagnostic_code == DiagnosticCode.SPE_PHY_TRAINING_LOSS
        assert engine.diagnostic_code == 0xEE51
        assert engine.diagnostic_code == -4527
        assert engine.link_state == SafeSPEState.SAFE_STOP_TRIPPED
        assert engine.operational is False
        assert engine.tripped is True
        assert engine.is_healthy is False

        # Register table reflections
        assert rt.read_word("%R2260") == 4
        assert rt.read_uword("%R2267") == 0xEE51
        assert rt.read_word("%R2267") == -4527
        assert rt.read_bit("%M527") is False
        assert rt.read_bit("%M528") is True

    def test_open_circuit_loop_resistance_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        # Resistance > 25,000 mOhm triggers open circuit trip
        engine.update_loop_resistance(26000)
        assert engine.diagnostic_code == DiagnosticCode.SPE_PHY_TRAINING_LOSS
        assert engine.diagnostic_code == 0xEE51
        assert engine.tripped is True
        assert engine.operational is False
        assert rt.read_word("%R2261") == 26000
        assert rt.read_uword("%R2267") == 0xEE51
        assert rt.read_bit("%M528") is True

    def test_short_circuit_loop_resistance_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        # Resistance <= 0 mOhm triggers short circuit trip
        engine.update_loop_resistance(0)
        assert engine.diagnostic_code == DiagnosticCode.SPE_PHY_TRAINING_LOSS
        assert engine.diagnostic_code == 0xEE51
        assert engine.tripped is True
        assert rt.read_word("%R2261") == 0
        assert rt.read_bit("%M528") is True

    def test_property_setter_loop_resistance_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.loop_resistance_milliohm = 30000
        assert engine.diagnostic_code == 0xEE51
        assert engine.tripped is True
        assert rt.read_bit("%M528") is True

    def test_loop_resistance_property_aliases(self) -> None:
        engine = CIPSafetySPEEngine(auto_activate=True)
        assert engine.loop_resistance == 1850

        engine.loop_resistance = 1900
        assert engine.loop_resistance_milliohm == 1900
        assert engine.loop_resistance == 1900

    def test_update_loop_resistance_nominal_and_scan_step_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        # Update to nominal valid resistance
        engine.update_loop_resistance(2000)
        assert engine.tripped is False
        assert rt.read_word("%R2261") == 2000

        # Scan step with resistance out of range trips
        engine._loop_resistance_milliohm = 28000
        engine.scan_step(0.001)
        assert engine.tripped is True
        assert engine.diagnostic_code == 0xEE51
        assert rt.read_uword("%R2267") == 0xEE51

    def test_phy_training_loss_recovery_reset(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.trip_phy_training_loss()
        assert engine.tripped is True

        engine.operator_reset()
        assert engine.diagnostic_code == 0x0000
        assert engine.loop_resistance_milliohm == 1850
        assert engine.tripped is False
        assert engine.operational is True
        assert rt.read_word("%R2261") == 1850
        assert rt.read_bit("%M527") is True
        assert rt.read_bit("%M528") is False


# ============================================================================
# 5. TestSnrDegradationTrip
# ============================================================================

class TestSnrDegradationTrip:
    """Validate 10BASE-T1L SNR margin degradation trip (0xEE52) and coil %M528."""

    def test_snr_drop_below_threshold_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        # Nominal is 245 (24.5 dB), threshold is 60 (6.0 dB)
        # Drop to 50 (5.0 dB)
        engine.update_snr(50)

        assert engine.diagnostic_code == DiagnosticCode.SPE_SNR_DEGRADATION_TRIP
        assert engine.diagnostic_code == 0xEE52
        assert engine.diagnostic_code == -4526
        assert engine.link_state == SafeSPEState.SAFE_STOP_TRIPPED
        assert engine.operational is False
        assert engine.tripped is True
        assert engine.is_healthy is False

        # Register reflection
        assert rt.read_word("%R2260") == 4
        assert rt.read_word("%R2262") == 50
        assert rt.read_uword("%R2267") == 0xEE52
        assert rt.read_bit("%M527") is False
        assert rt.read_bit("%M528") is True

    def test_manual_trip_snr_degradation(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.trip_snr_degradation("Noise floor spike on single pair")
        assert engine.diagnostic_code == 0xEE52
        assert engine.tripped is True
        assert rt.read_uword("%R2267") == 0xEE52
        assert rt.read_bit("%M528") is True

    def test_snr_property_setter_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.snr_margin_tenth_db = 40
        assert engine.diagnostic_code == 0xEE52
        assert engine.tripped is True
        assert rt.read_word("%R2262") == 40
        assert rt.read_bit("%M528") is True

    def test_snr_safe_boundary_no_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        # 60 tenth dB (6.0 dB) is exactly on the boundary, not strictly below
        engine.update_snr(60)
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.tripped is False
        assert engine.operational is True
        assert rt.read_word("%R2262") == 60
        assert rt.read_bit("%M527") is True
        assert rt.read_bit("%M528") is False

    def test_snr_degradation_recovery_reset(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.update_snr(30)
        assert engine.tripped is True

        engine.fault_reset()
        assert engine.diagnostic_code == 0x0000
        assert engine.snr_margin_tenth_db == 245
        assert engine.tripped is False
        assert engine.operational is True
        assert rt.read_word("%R2262") == 245
        assert rt.read_bit("%M527") is True
        assert rt.read_bit("%M528") is False

    def test_snr_margin_aliases_and_update_metrics(self) -> None:
        engine = CIPSafetySPEEngine(auto_activate=True)
        assert engine.snr_margin == 245

        engine.snr_margin = 250
        assert engine.snr_margin_tenth_db == 250
        assert engine.snr_margin == 250

        # update_phy_metrics
        engine.update_phy_metrics(snr_margin_tenth_db=260, loop_resistance_milliohm=1950)
        assert engine.snr_margin_tenth_db == 260
        assert engine.loop_resistance_milliohm == 1950

    def test_scan_step_snr_degradation_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine._snr_margin_tenth_db = 45  # < 60 threshold
        engine.scan_step(0.001)
        assert engine.tripped is True
        assert engine.diagnostic_code == 0xEE52
        assert rt.read_uword("%R2267") == 0xEE52


# ============================================================================
# 6. TestSafetyCrcFaultTrip
# ============================================================================

class TestSafetyCrcFaultTrip:
    """Validate safety dual-CRC fault trip (0xEE53), sequence verification, SNN verification, and coil %M528."""

    def test_corrupted_frame_reception_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        # Create valid frame then corrupt a single bit
        frame = create_valid_spe_safety_frame(sequence_primary=12)
        frame.mutate_bit(byte_offset=1, bit_pos=3)

        assert engine.receive_frame(frame) is False
        assert engine.diagnostic_code == DiagnosticCode.SPE_SAFETY_CRC_FAULT
        assert engine.diagnostic_code == 0xEE53
        assert engine.diagnostic_code == -4525
        assert engine.link_state == SafeSPEState.SAFE_STOP_TRIPPED
        assert engine.rx_crc_error_count == 1
        assert engine.tripped is True
        assert engine.operational is False

        # Register reflection
        assert rt.read_word("%R2260") == 4
        assert rt.read_word("%R2265") == 1
        assert rt.read_uword("%R2267") == 0xEE53
        assert rt.read_bit("%M527") is False
        assert rt.read_bit("%M528") is True

    def test_sequence_inversion_mismatch_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        # Create frame with corrupted diversified sequence
        frame = create_valid_spe_safety_frame(sequence_primary=20)
        frame.sequence_diversified = 12345  # Not (~20 & 0xFFFF)
        # Recompute CRCs over corrupt frame so CRC check might pass or fail
        frame.calculate_crcs()

        assert engine.receive_frame(frame) is False
        assert engine.diagnostic_code == DiagnosticCode.SPE_SAFETY_CRC_FAULT
        assert engine.tripped is True
        assert rt.read_uword("%R2267") == 0xEE53
        assert rt.read_bit("%M528") is True

    def test_snn_mismatch_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        # Create frame with wrong SNN (e.g. 0x9999 instead of 0x1A2B)
        frame = create_valid_spe_safety_frame(sequence_primary=30, snn=0x9999)
        assert frame.verify_crcs() is True

        assert engine.receive_frame(frame) is False
        assert engine.diagnostic_code == DiagnosticCode.SPE_SAFETY_CRC_FAULT
        assert engine.tripped is True
        assert rt.read_uword("%R2267") == 0xEE53
        assert rt.read_bit("%M528") is True

    def test_direct_trip_safety_crc_fault(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.trip_safety_crc_fault("Explicit CRC fault injection")
        assert engine.diagnostic_code == 0xEE53
        assert engine.rx_crc_error_count == 1
        assert engine.tripped is True
        assert rt.read_word("%R2265") == 1
        assert rt.read_uword("%R2267") == 0xEE53
        assert rt.read_bit("%M528") is True

    def test_valid_frame_transmission_and_reception(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        # Send frame
        f_tx = engine.create_frame(payload=b"\x01\x02\x03\x04")
        assert engine.send_frame(f_tx) is True
        assert engine.tx_frame_count == 101
        assert rt.read_word("%R2264") == 101

        # Receive valid frame
        f_rx = create_valid_spe_safety_frame(sequence_primary=10, snn=0x1A2B)
        assert engine.receive_frame(f_rx) is True
        assert engine.frames_received == 1
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.tripped is False

    def test_crc_fault_recovery_reset(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.trip_safety_crc_fault()
        assert engine.rx_crc_error_count == 1
        assert engine.tripped is True

        engine.reset()
        assert engine.diagnostic_code == 0x0000
        assert engine.rx_crc_error_count == 0
        assert engine.tripped is False
        assert engine.operational is True
        assert rt.read_word("%R2265") == 0
        assert rt.read_uword("%R2267") == 0x0000
        assert rt.read_bit("%M527") is True
        assert rt.read_bit("%M528") is False

    def test_snn_aliases_and_setters(self) -> None:
        engine = CIPSafetySPEEngine(auto_activate=True)
        assert engine.snn == 0x1A2B

        engine.snn = 0x5566
        assert engine.safety_network_number == 0x5566
        assert engine.snn == 0x5566

    def test_send_and_receive_while_tripped_returns_false(self) -> None:
        engine = CIPSafetySPEEngine(auto_activate=True)
        engine.trip_safety_crc_fault()

        f = create_valid_spe_safety_frame()
        assert engine.send_frame(f) is False
        assert engine.receive_frame(f) is False

    def test_rx_crc_error_count_setter_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.rx_crc_error_count = 2
        assert engine.tripped is True
        assert engine.diagnostic_code == 0xEE53
        assert engine.rx_crc_error_count == 2
        assert rt.read_word("%R2265") == 2


# ============================================================================
# 7. TestEpiTimeoutTrip
# ============================================================================

class TestEpiTimeoutTrip:
    """Validate EPI Expected Packet Interval watchdog surveillance (>= 15000 us trips 0xEE54) and coil %M528."""

    def test_epi_timer_exceeds_watchdog_threshold(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        # Nominal is 2500 us, threshold is 15000 us
        engine.update_epi_timer(15000)

        assert engine.diagnostic_code == DiagnosticCode.SPE_EPI_TIMEOUT_TRIP
        assert engine.diagnostic_code == 0xEE54
        assert engine.diagnostic_code == -4524
        assert engine.link_state == SafeSPEState.SAFE_STOP_TRIPPED
        assert engine.operational is False
        assert engine.tripped is True
        assert engine.is_healthy is False

        # Register reflection
        assert rt.read_word("%R2260") == 4
        assert rt.read_word("%R2266") == 15000
        assert rt.read_uword("%R2267") == 0xEE54
        assert rt.read_bit("%M527") is False
        assert rt.read_bit("%M528") is True

    def test_scan_step_advances_epi_and_trips(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        # 13 scans of 1 ms = 13,000 us added to nominal 2,500 us = 15,500 us -> trips!
        for _ in range(13):
            engine.scan_step(0.001)

        assert engine.diagnostic_code == DiagnosticCode.SPE_EPI_TIMEOUT_TRIP
        assert engine.diagnostic_code == 0xEE54
        assert engine.tripped is True
        assert rt.read_uword("%R2267") == 0xEE54
        assert rt.read_bit("%M528") is True

    def test_feed_watchdog_prevents_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        # Advance 2 ms
        engine.scan_step(0.002)
        assert engine.tripped is False

        # Feed watchdog
        engine.feed_watchdog(reset_epi_us=2500)
        assert engine.epi_timer_us == 2500
        assert engine.tripped is False

        # Advance another 2 ms (total elapsed 4 ms, but reset kept it safe)
        engine.scan_step(0.002)
        assert engine.tripped is False
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert rt.read_bit("%M527") is True
        assert rt.read_bit("%M528") is False

    def test_direct_trip_epi_timeout(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.trip_epi_timeout("Watchdog expired")
        assert engine.diagnostic_code == 0xEE54
        assert engine.tripped is True
        assert rt.read_uword("%R2267") == 0xEE54
        assert rt.read_bit("%M528") is True

    def test_epi_timeout_recovery_reset(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.update_epi_timer(9000)
        assert engine.tripped is True

        engine.reset()
        assert engine.diagnostic_code == 0x0000
        assert engine.epi_timer_us == 2500
        assert engine.tripped is False
        assert engine.operational is True
        assert rt.read_word("%R2266") == 2500
        assert rt.read_uword("%R2267") == 0x0000
        assert rt.read_bit("%M527") is True
        assert rt.read_bit("%M528") is False

    def test_epi_timer_us_setter_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.epi_timer_us = 8500
        assert engine.tripped is True
        assert engine.diagnostic_code == 0xEE54
        assert rt.read_word("%R2266") == 8500

    def test_diagnostic_code_setter_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.diagnostic_code = 0xEE52
        assert engine.tripped is True
        assert engine.operational is False
        assert engine.link_state == SafeSPEState.SAFE_STOP_TRIPPED
        assert rt.read_uword("%R2267") == 0xEE52

    def test_update_epi_timer_nominal(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.update_epi_timer(3000)
        assert engine.tripped is False
        assert rt.read_word("%R2266") == 3000


# ============================================================================
# 8. TestRegisterSynchronization
# ============================================================================

class TestRegisterSynchronization:
    """Validate bit-exact synchronization to Horner OCS %R2260..%R2267 and %M527..%M528."""

    def test_nominal_register_synchronization(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        assert rt.read_word("%R2260") == 3
        assert rt.read_word("%R2261") == 1850
        assert rt.read_word("%R2262") == 245
        assert rt.read_uword("%R2263") == 0x1A2B
        assert rt.read_word("%R2264") == 100
        assert rt.read_word("%R2265") == 0
        assert rt.read_word("%R2266") == 2500
        assert rt.read_uword("%R2267") == 0x0000
        assert rt.read_bit("%M527") is True
        assert rt.read_bit("%M528") is False

    def test_sequential_fault_trips_sync(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        fault_cases = [
            (DiagnosticCode.SPE_PHY_TRAINING_LOSS, 0xEE51),
            (DiagnosticCode.SPE_SNR_DEGRADATION_TRIP, 0xEE52),
            (DiagnosticCode.SPE_SAFETY_CRC_FAULT, 0xEE53),
            (DiagnosticCode.SPE_EPI_TIMEOUT_TRIP, 0xEE54),
        ]

        for code, hex_code in fault_cases:
            engine.trip_fault(code)
            assert rt.read_word("%R2260") == 4
            assert rt.read_uword("%R2267") == hex_code
            assert rt.read_bit("%M527") is False
            assert rt.read_bit("%M528") is True

            engine.reset()
            assert rt.read_word("%R2260") == 3
            assert rt.read_uword("%R2267") == 0x0000
            assert rt.read_bit("%M527") is True
            assert rt.read_bit("%M528") is False

    def test_property_setters_sync(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        engine.loop_resistance_milliohm = 2100
        assert rt.read_word("%R2261") == 2100

        engine.snr_margin_tenth_db = 280
        assert rt.read_word("%R2262") == 280

        engine.safety_network_number = 0x3344
        assert rt.read_uword("%R2263") == 0x3344

        engine.tx_frame_count = 150
        assert rt.read_word("%R2264") == 150

        engine.rx_crc_error_count = 0
        assert rt.read_word("%R2265") == 0

        engine.epi_timer_us = 3000
        assert rt.read_word("%R2266") == 3000

    def test_safe_write_wrappers(self) -> None:
        rt = RegisterTable()

        # Word wrapping test (> 32767 wraps to negative signed)
        safe_write_word(rt, "%R2260", 40000)
        assert rt.read_word("%R2260") == 40000 - 65536

        # UWord test
        safe_write_uword(rt, "%R2267", 0xEE51)
        assert rt.read_uword("%R2267") == 0xEE51

        # Bit test
        safe_write_bit(rt, "%M527", True)
        assert rt.read_bit("%M527") is True
        safe_write_bit(rt, "%M527", False)
        assert rt.read_bit("%M527") is False


# ============================================================================
# 9. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 ST POU verification with SecurityGuard and STParser."""

    def test_pure_st_pou_verification(self) -> None:
        assert verify_cip_safety_spe_pure_st() is True
        assert verify_cip_safety_spe_pure_st(CIP_SAFETY_SPE_PURE_ST_POU) is True
        assert verify_cip_safety_spe_pure_st(CIP_SAFETY_SPE_SYNC_POU) is True
        assert verify_cip_safety_spe_pure_st(CIP_SAFETY_SPE_POU) is True
        assert verify_cip_safety_spe_pure_st(PURE_ST_POU) is True
        assert verify_cip_safety_spe_pure_st(CipSafetySpeSync) is True
        assert verify_cip_safety_spe_pure_st(CipSafetySpeSyncPOU) is True

    def test_security_guard_and_st_parser(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_SPE_PURE_ST_POU)
        res = STParser.validate_code(CIP_SAFETY_SPE_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(CIP_SAFETY_SPE_PURE_ST_POU)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R2260", "%R2261", "%R2262", "%R2263",
            "%R2264", "%R2265", "%R2266", "%R2267",
            "%M527", "%M528",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_ast_variable_memory_address_mappings(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_SPE_PURE_ST_POU)
        var_map = {
            v.name: getattr(v, "memory_address", getattr(v, "address_binding", None))
            for v in ast.variables
        }

        assert var_map["LinkState"] == "%R2260"
        assert var_map["LoopResistanceMilliOhm"] == "%R2261"
        assert var_map["SnrMarginTenthDb"] == "%R2262"
        assert var_map["SafetyNetworkNumber"] == "%R2263"
        assert var_map["TxFrameCount"] == "%R2264"
        assert var_map["RxCrcErrorCount"] == "%R2265"
        assert var_map["EpiTimerUs"] == "%R2266"
        assert var_map["DiagnosticCode"] == "%R2267"
        assert var_map["OperationalCoil"] == "%M527"
        assert var_map["TrippedCoil"] == "%M528"

    def test_invalid_pou_fails_verification(self) -> None:
        invalid_pou = "PROGRAM CorruptPOU VAR X : INT; END_VAR X := 10; END_PROGRAM"
        assert verify_cip_safety_spe_pure_st(invalid_pou) is False


# ============================================================================
# 10. TestAntiLadderConstructRejection
# ============================================================================

class TestAntiLadderConstructRejection:
    """Verify security guard immediately rejects ladder constructs with LadderForbiddenError."""

    @pytest.mark.parametrize(
        "construct",
        [
            "---[ ]---",
            "---[/]---",
            "---( )---",
            "---(S)---",
            "---(R)---",
            "RUNG 10",
            "NETWORK 1",
            "XIC(Channel1);",
            "OTE(Coil1);",
            "OTL(Latch1);",
            "OTU(Unlatch1);",
        ],
    )
    def test_ladder_constructs_rejected(self, construct: str) -> None:
        snippet = f"PROGRAM TestLadder\n VAR b : BOOL; END_VAR\n {construct}\n END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# 11. TestILogicUnitComplianceAndSoak
# ============================================================================

class TestILogicUnitComplianceAndSoak:
    """Verify ILogicUnit compliance: properties, scan_step, step, execute, reset, and 100-cycle soak."""

    def test_ilogicunit_interface_properties(self) -> None:
        engine = CIPSafetySPEEngine(auto_activate=True)
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "CIPSafetySPEEngine"
        assert engine.priority == 10
        assert engine.is_enabled is True
        assert engine.is_healthy is True
        assert engine.is_tripped is False
        assert engine.link_state == SafeSPEState.SAFE_OPERATIONAL

    def test_scan_step_and_step(self) -> None:
        engine = CIPSafetySPEEngine(auto_activate=True)
        assert engine.cycles_count == 0
        engine.scan_step(0.001)
        assert engine.cycles_count == 1

        engine.step(0.001)
        assert engine.cycles_count == 2

    def test_execute_scan_context(self) -> None:
        engine = CIPSafetySPEEngine(auto_activate=True)
        ctx = ScanContext(cycle=1, dt_ms=1.0)
        engine.execute(ctx)
        assert engine.cycles_count == 1

    def test_100_cycle_soak_stability_and_heap_boundedness(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetySPEEngine(register_table=rt, auto_activate=True)

        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        for cycle_i in range(1, 101):
            engine.feed_watchdog(reset_epi_us=2500)
            engine.scan_step(0.001)

        snapshot_after = tracemalloc.take_snapshot()
        stats = snapshot_after.compare_to(snapshot_before, "lineno")
        heap_growth_kb = sum(st.size_diff for st in stats if st.size_diff > 0) / 1024.0
        tracemalloc.stop()

        assert engine.cycles_count == 100
        assert heap_growth_kb < 100.0
        assert engine.link_state == SafeSPEState.SAFE_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_healthy is True
        assert engine.tripped is False
        assert rt.read_word("%R2260") == 3
        assert rt.read_uword("%R2267") == 0x0000
        assert rt.read_bit("%M527") is True
        assert rt.read_bit("%M528") is False


# ============================================================================
# 12. TestExceptionsAndVerificationRunner
# ============================================================================

class TestExceptionsAndVerificationRunner:
    """Verify custom exception inheritance, 10-stage verification runner, and strict 4-state contract."""

    def test_exception_inheritance_hierarchy(self) -> None:
        assert issubclass(CIPSafetySPEPhyTrainingLossError, CIPSafetySPEError)
        assert issubclass(CIPSafetySPESnrDegradationError, CIPSafetySPEError)
        assert issubclass(CIPSafetySPECRCFaultError, CIPSafetySPEError)
        assert issubclass(CIPSafetySPEEpiTimeoutError, CIPSafetySPEError)
        assert issubclass(CIPSafetySPEError, Exception)

        # Aliases
        assert SPESafetyError is CIPSafetySPEError
        assert CipSafetySpeError is CIPSafetySPEError
        assert SPEPhyTrainingLossError is CIPSafetySPEPhyTrainingLossError
        assert SPESnrDegradationError is CIPSafetySPESnrDegradationError
        assert SPECRCFaultError is CIPSafetySPECRCFaultError
        assert SPEEpiTimeoutError is CIPSafetySPEEpiTimeoutError

    def test_verification_runner_execution(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = tf.name

        try:
            result = run_cip_safety_spe_verification(output_path=temp_path)
            assert isinstance(result, dict)
            assert result["status"] == "success"
            assert result["error_code"] is None
            assert result["stages_passed"] == 10
            assert result["total_stages"] == 10
            assert result["work_package"] == "W265"

            # Verify saved JSON evidence
            with open(temp_path, "r", encoding="utf-8") as f:
                saved_evidence = json.load(f)
            assert saved_evidence["status"] == "success"
            assert saved_evidence["stages_passed"] == 10
        finally:
            Path(temp_path).unlink(missing_ok=True)
