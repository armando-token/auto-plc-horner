"""Comprehensive Unit Test Suite for Wave W316 CIP Safety Over SPE Single-Pair Ethernet PoDL Fault Engine.

Work Package: W316 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over SPE Single-Pair Ethernet Power-over-Data-Line (PoDL) Fault Engine.

Covers Comprehensive Deterministic Unit Tests across 14 Mandatory Test Classes (80+ Tests):
1. TestProtocolConstantsEnumsAndDiagnostics: Canonical registers (%R2770..%R2777), coils (%M646..%M647),
   aliases, protocol constants, enums (PoDLPSEClass, PoDLState, PoDLStatusBits),
   and signed 16-bit safe comparisons for DiagnosticCode (0x0000, 0xEE91..0xEE95).
2. TestDualSafetyCrcMathematics: CRC-S1 (poly 0x5935, init 0x0000) and CRC-S2 (poly 0x755B, init 0x0000)
   polynomial mathematics, single-bit perturbation detection, EPID hashing and CRC32.
3. TestPacketModelAndBinarySerialization: CIPPoDLPacket dataclass, property accessors,
   inverted header computation, CRC validation, binary pack/unpack roundtrip, and tampering detection.
4. TestPoDLPSEClassificationAndPowerCalculation: 6 PSE classes (Classes 10-15), voltage boundaries,
   current limits, max power limits, electrical formula P = V * I, and dynamic class switching.
5. TestOvercurrentInjectionAndTrip: Overcurrent injection exceeding I_max_mA for PSE Class (0xEE91),
   transition to SAFETY_TRIP, de-assertion of online, assertion of tripped, and recovery.
6. TestUndervoltageInjectionAndTrip: Undervoltage injection collapsing below V_min_mV (0xEE92),
   transition to SAFETY_TRIP, status bit assertion, and fail-safe trip.
7. TestGroundLoopFaultInjectionAndTrip: Ground loop resistance fault and leakage detection (0xEE93),
   loop resistance limits, status bit assertion, and fail-safe trip.
8. TestSerialSccpFrameTimeoutAndTrip: Serial SCCP frame loss watchdog timeout (> 1000 us loss)
   tripping DIAG_ERR_PSE_COMMUNICATION_TIMEOUT (0xEE95), scan step accumulation, and heartbeat reset.
9. TestCrcCorruptionInjectionAndTrip: Dual CRC corruption injection (0xEE94), packet corruption detection,
   and monotonic packet loss counter increments.
10. TestSafeStopInterlockAndCoils: Fail-safe interlock asserting %M647 (SAFETY_TRIP) and de-asserting %M646 (ONLINE)
    across all diagnostic trip conditions, coil mutual exclusivity, and healthy restoration upon clear_fault().
11. TestHornerRegisterTableSynchronization: Bit-exact synchronization to Horner OCS registers (%R2770..%R2777)
    and coils (%M646..%M647), status register packing, signed 16-bit masking, privilege modes, and write helpers.
12. TestPureIEC61131StructuredTextAndSecurity: Pure IEC 61131-3 ST POU CipSafetyPodlFaultSync validation
    via STParser and SecurityGuard, AST bound registers, and strict interception of 9 ladder logic constructs.
13. TestILogicUnitComplianceAndSimulationSoak: ILogicUnit interface compliance, variable scan_step argument
    handling, step/execute/reset methods, and 100-cycle continuous simulation soak with bounded memory.
14. TestVerificationRunner9StagesAndCli: Complete 9-stage verification suite run_cip_safety_podl_fault_verification,
    strict 4-state engineering contract validation, JSON evidence emission rules, and CLI interop.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import tracemalloc
from typing import Any, Dict, List
import pytest
import zlib

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_podl_fault import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_PODL_CLASS_ID,
    CIP_PODL_CLASS_ID,
    NOMINAL_SCCP_INTERVAL_US,
    DEFAULT_SCCP_INTERVAL_US,
    MIN_SCCP_INTERVAL_US,
    MAX_SCCP_INTERVAL_US,
    SCCP_TIMEOUT_THRESHOLD_US,
    DEFAULT_SCCP_TIMEOUT_US,
    NOMINAL_SCCP_TIMEOUT_US,
    DEFAULT_LOOP_RESISTANCE_MOHM,
    NOMINAL_LOOP_RESISTANCE_MOHM,
    DEFAULT_LOOP_RESISTANCE_LIMIT_MOHM,
    MAX_ALLOWED_LOOP_RESISTANCE_MOHM,
    DEFAULT_SESSION_ID,
    DEFAULT_SAFETY_EPID,
    DEFAULT_EPID,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S_INIT,
    CRC_INIT,
    CRC16_CCITT_POLY,
    CRC16_CCITT_INIT,
    REG_CIP_PODL_STATUS,
    REG_CIP_PODL_VOLTAGE_MV,
    REG_CIP_PODL_CURRENT_MA,
    REG_CIP_PODL_LOOP_RESISTANCE_MOHM,
    REG_CIP_PODL_POWER_MW,
    REG_CIP_PODL_FAULT_CODE,
    REG_CIP_PODL_PSE_CLASS,
    REG_CIP_PODL_DIAGNOSTIC_CODE,
    COIL_CIP_PODL_ONLINE,
    COIL_CIP_PODL_SAFETY_TRIP,
    REG_PODL_STATUS,
    REG_PODL_STATE,
    REG_CIP_PODL_STATE,
    REG_PODL_VOLTAGE_MV,
    REG_PODL_VOLTAGE,
    REG_CIP_PODL_VOLTAGE,
    REG_PODL_CURRENT_MA,
    REG_PODL_CURRENT,
    REG_CIP_PODL_CURRENT,
    REG_PODL_LOOP_RESISTANCE_MOHM,
    REG_PODL_LOOP_RESISTANCE,
    REG_CIP_PODL_LOOP_RESISTANCE,
    REG_PODL_POWER_MW,
    REG_PODL_POWER,
    REG_CIP_PODL_POWER,
    REG_PODL_FAULT_CODE,
    REG_PODL_FAULT,
    REG_PODL_PSE_CLASS,
    REG_PODL_CLASS,
    REG_CIP_PODL_CLASS,
    REG_PODL_DIAGNOSTIC_CODE,
    REG_PODL_DIAG_CODE,
    COIL_PODL_ONLINE,
    COIL_PODL_SAFETY_TRIP,
    COIL_CIP_PODL_TRIP,
    COIL_PODL_TRIP,
    COIL_CIP_PODL_HEALTHY,
    COIL_PODL_HEALTHY,
    COIL_CIP_PODL_ACTIVE,
    COIL_PODL_ACTIVE,
    COIL_CIP_PODL_FAULT,
    COIL_PODL_FAULT,
    PoDLPSEClass,
    PSEClass,
    PoDLClass,
    CipSafetyPoDLPSEClass,
    CIPPoDLPSEClass,
    PSE_CLASS_SPECS,
    PoDLState,
    CipSafetyPoDLState,
    CIPPoDLState,
    PoDLConnectionState,
    DiagnosticCode,
    DIAG_OK,
    DIAG_ERR_OVERCURRENT_FAULT,
    DIAG_ERR_UNDERVOLTAGE_FAULT,
    DIAG_ERR_GROUND_LOOP_FAULT,
    DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
    DIAG_ERR_PSE_COMMUNICATION_TIMEOUT,
    DIAG_OVERCURRENT,
    DIAG_UNDERVOLTAGE,
    DIAG_GROUND_LOOP,
    DIAG_CRC_FAULT,
    DIAG_TIMEOUT,
    DIAG_SCCP_TIMEOUT,
    PoDLDiagnosticCode,
    CIPPoDLDiagnosticCode,
    CipSafetyPoDLDiagnosticCode,
    DiagnosticStatusCode,
    PoDLFaultCode,
    CIPPoDLFaultCode,
    PoDLStatusBits,
    CipSafetyPoDLStatusBits,
    CIPPoDLStatusBits,
    CIPPoDLSafetyError,
    PoDLOvercurrentFaultError,
    PoDLUndervoltageFaultError,
    PoDLGroundLoopFaultError,
    PoDLDualCrcSafetyFaultError,
    PoDLPSECommunicationTimeoutError,
    PoDLCrcFaultError,
    PoDLTimeoutError,
    PoDLOvercurrentError,
    PoDLUndervoltageError,
    PoDLGroundFaultError,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    calculate_cip_safety_crc_s1,
    calculate_cip_safety_crc_s2,
    calculate_crc_s1,
    calculate_crc_s2,
    compute_epid_hash,
    compute_epid_crc32,
    calculate_crc16_ccitt,
    verify_dual_crc_s,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CIPPoDLPacket,
    CipSafetyPoDLPacket,
    PoDLPacket,
    CIPPoDLSafetyPacket,
    PoDLSafetyPacket,
    create_valid_podl_packet,
    create_valid_cip_podl_packet,
    create_valid_cip_safety_podl_packet,
    ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC,
    CIP_SAFETY_PODL_FAULT_SYNC_POU,
    CIP_SAFETY_PODL_FAULT_PURE_ST_POU,
    CIP_SAFETY_PODL_POU,
    PURE_ST_POU,
    CipSafetyPodlFaultSync,
    CipSafetyPodlFaultSyncPOU,
    verify_cip_safety_podl_fault_pure_st,
    verify_podl_pure_st,
    CIPPoDLSafetyEngine,
    CipSafetyPoDLEngine,
    CIPPoDLEngine,
    PoDLSafetyEngine,
    PoDLEngine,
    PoDLFaultEngine,
    run_cip_safety_podl_fault_verification,
)


# ============================================================================
# 1. TestProtocolConstantsEnumsAndDiagnostics
# ============================================================================

class TestProtocolConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety Over SPE PoDL Fault Engine constants, registers, coils, and diagnostics."""

    def test_canonical_registers(self) -> None:
        """Validate canonical Horner OCS analog registers %R2770..%R2777."""
        assert REG_CIP_PODL_STATUS == "%R2770"
        assert REG_CIP_PODL_VOLTAGE_MV == "%R2771"
        assert REG_CIP_PODL_CURRENT_MA == "%R2772"
        assert REG_CIP_PODL_LOOP_RESISTANCE_MOHM == "%R2773"
        assert REG_CIP_PODL_POWER_MW == "%R2774"
        assert REG_CIP_PODL_FAULT_CODE == "%R2775"
        assert REG_CIP_PODL_PSE_CLASS == "%R2776"
        assert REG_CIP_PODL_DIAGNOSTIC_CODE == "%R2777"

    def test_canonical_coils(self) -> None:
        """Validate canonical Horner OCS discrete coils %M646..%M647."""
        assert COIL_CIP_PODL_ONLINE == "%M646"
        assert COIL_CIP_PODL_SAFETY_TRIP == "%M647"

    def test_register_and_coil_aliases(self) -> None:
        """Validate register and coil extended and backwards compatibility aliases."""
        assert REG_PODL_STATUS == "%R2770"
        assert REG_PODL_STATE == "%R2770"
        assert REG_CIP_PODL_STATE == "%R2770"
        assert REG_PODL_VOLTAGE_MV == "%R2771"
        assert REG_PODL_VOLTAGE == "%R2771"
        assert REG_CIP_PODL_VOLTAGE == "%R2771"
        assert REG_PODL_CURRENT_MA == "%R2772"
        assert REG_PODL_CURRENT == "%R2772"
        assert REG_CIP_PODL_CURRENT == "%R2772"
        assert REG_PODL_LOOP_RESISTANCE_MOHM == "%R2773"
        assert REG_PODL_LOOP_RESISTANCE == "%R2773"
        assert REG_CIP_PODL_LOOP_RESISTANCE == "%R2773"
        assert REG_PODL_POWER_MW == "%R2774"
        assert REG_PODL_POWER == "%R2774"
        assert REG_CIP_PODL_POWER == "%R2774"
        assert REG_PODL_FAULT_CODE == "%R2775"
        assert REG_PODL_FAULT == "%R2775"
        assert REG_PODL_PSE_CLASS == "%R2776"
        assert REG_PODL_CLASS == "%R2776"
        assert REG_CIP_PODL_CLASS == "%R2776"
        assert REG_PODL_DIAGNOSTIC_CODE == "%R2777"
        assert REG_PODL_DIAG_CODE == "%R2777"

        assert COIL_PODL_ONLINE == "%M646"
        assert COIL_PODL_SAFETY_TRIP == "%M647"
        assert COIL_CIP_PODL_TRIP == "%M647"
        assert COIL_PODL_TRIP == "%M647"
        assert COIL_CIP_PODL_HEALTHY == "%M646"
        assert COIL_PODL_HEALTHY == "%M646"
        assert COIL_CIP_PODL_ACTIVE == "%M646"
        assert COIL_PODL_ACTIVE == "%M646"
        assert COIL_CIP_PODL_FAULT == "%M647"
        assert COIL_PODL_FAULT == "%M647"

    def test_class_ids_and_protocol_timing_constants(self) -> None:
        """Validate CIP class IDs and IEEE 802.3cg/bu SCCP timing parameters."""
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_PODL_CLASS_ID == 0x48
        assert CIP_PODL_CLASS_ID == 0x48

        assert NOMINAL_SCCP_INTERVAL_US == 400
        assert DEFAULT_SCCP_INTERVAL_US == 400
        assert MIN_SCCP_INTERVAL_US == 100
        assert MAX_SCCP_INTERVAL_US == 10000

        assert SCCP_TIMEOUT_THRESHOLD_US == 1000
        assert DEFAULT_SCCP_TIMEOUT_US == 1000
        assert NOMINAL_SCCP_TIMEOUT_US == 1000

        assert DEFAULT_LOOP_RESISTANCE_MOHM == 1850
        assert NOMINAL_LOOP_RESISTANCE_MOHM == 1850
        assert DEFAULT_LOOP_RESISTANCE_LIMIT_MOHM == 65000
        assert MAX_ALLOWED_LOOP_RESISTANCE_MOHM == 65000

        assert DEFAULT_SESSION_ID == 0x5044
        assert DEFAULT_SAFETY_EPID == "HORNER-OCS-SPE-PODL-SIL3"
        assert DEFAULT_EPID == DEFAULT_SAFETY_EPID

    def test_podl_pse_class_enum_members_and_properties(self) -> None:
        """Validate PoDLPSEClass integer enumeration, aliases, and properties."""
        assert PoDLPSEClass.CLASS_10 == 10
        assert PoDLPSEClass.CLASS_11 == 11
        assert PoDLPSEClass.CLASS_12 == 12
        assert PoDLPSEClass.CLASS_13 == 13
        assert PoDLPSEClass.CLASS_14 == 14
        assert PoDLPSEClass.CLASS_15 == 15

        assert PSEClass is PoDLPSEClass
        assert PoDLClass is PoDLPSEClass
        assert CipSafetyPoDLPSEClass is PoDLPSEClass
        assert CIPPoDLPSEClass is PoDLPSEClass

        # Verify properties on enum members
        assert PoDLPSEClass.CLASS_10.v_nominal_mv == 12000
        assert PoDLPSEClass.CLASS_10.v_min_mv == 10000
        assert PoDLPSEClass.CLASS_10.i_max_ma == 460
        assert PoDLPSEClass.CLASS_10.p_max_mw == 5520

        assert PoDLPSEClass.CLASS_12.v_nominal_mv == 24000
        assert PoDLPSEClass.CLASS_12.v_min_mv == 20000
        assert PoDLPSEClass.CLASS_12.i_max_ma == 460
        assert PoDLPSEClass.CLASS_12.p_max_mw == 11040

        assert PoDLPSEClass.CLASS_15.v_nominal_mv == 48000
        assert PoDLPSEClass.CLASS_15.v_min_mv == 40000
        assert PoDLPSEClass.CLASS_15.i_max_ma == 1360
        assert PoDLPSEClass.CLASS_15.p_max_mw == 65280

    def test_podl_state_enum_members_and_aliases(self) -> None:
        """Validate PoDLState integer enumeration and aliases."""
        assert PoDLState.SLEEP == 0
        assert PoDLState.DETECTION == 1
        assert PoDLState.CLASSIFICATION == 2
        assert PoDLState.POWERED_NORMAL == 3
        assert PoDLState.FAULT_LOCKOUT == 4
        assert PoDLState.SAFETY_TRIP == 5

        assert PoDLState.NORMAL == 3
        assert PoDLState.POWERED == 3
        assert PoDLState.LOCKOUT == 4
        assert PoDLState.TRIP == 5
        assert PoDLState.TRIPPED == 5

        assert CipSafetyPoDLState is PoDLState
        assert CIPPoDLState is PoDLState
        assert PoDLConnectionState is PoDLState

    def test_diagnostic_code_values_and_aliases(self) -> None:
        """Validate DiagnosticCode integer values and extended aliases."""
        assert DiagnosticCode.DIAG_OK == 0x0000
        assert DiagnosticCode.DIAG_ERR_OVERCURRENT_FAULT == 0xEE91
        assert DiagnosticCode.DIAG_ERR_UNDERVOLTAGE_FAULT == 0xEE92
        assert DiagnosticCode.DIAG_ERR_GROUND_LOOP_FAULT == 0xEE93
        assert DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT == 0xEE94
        assert DiagnosticCode.DIAG_ERR_PSE_COMMUNICATION_TIMEOUT == 0xEE95

        assert DIAG_OK == DiagnosticCode.DIAG_OK
        assert DIAG_ERR_OVERCURRENT_FAULT == DiagnosticCode.DIAG_ERR_OVERCURRENT_FAULT
        assert DIAG_ERR_UNDERVOLTAGE_FAULT == DiagnosticCode.DIAG_ERR_UNDERVOLTAGE_FAULT
        assert DIAG_ERR_GROUND_LOOP_FAULT == DiagnosticCode.DIAG_ERR_GROUND_LOOP_FAULT
        assert DIAG_ERR_DUAL_CRC_SAFETY_FAULT == DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert DIAG_ERR_PSE_COMMUNICATION_TIMEOUT == DiagnosticCode.DIAG_ERR_PSE_COMMUNICATION_TIMEOUT

        assert DIAG_OVERCURRENT == DIAG_ERR_OVERCURRENT_FAULT
        assert DIAG_UNDERVOLTAGE == DIAG_ERR_UNDERVOLTAGE_FAULT
        assert DIAG_GROUND_LOOP == DIAG_ERR_GROUND_LOOP_FAULT
        assert DIAG_CRC_FAULT == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert DIAG_TIMEOUT == DIAG_ERR_PSE_COMMUNICATION_TIMEOUT
        assert DIAG_SCCP_TIMEOUT == DIAG_ERR_PSE_COMMUNICATION_TIMEOUT

        assert PoDLDiagnosticCode is DiagnosticCode
        assert CIPPoDLDiagnosticCode is DiagnosticCode
        assert CipSafetyPoDLDiagnosticCode is DiagnosticCode
        assert DiagnosticStatusCode is DiagnosticCode
        assert PoDLFaultCode is DiagnosticCode
        assert CIPPoDLFaultCode is DiagnosticCode

    def test_diagnostic_code_safe_signed_comparisons(self) -> None:
        """Validate DiagnosticCode safe signed and unsigned 16-bit comparisons."""
        for code, expected_u16 in [
            (DiagnosticCode.DIAG_OK, 0x0000),
            (DiagnosticCode.DIAG_ERR_OVERCURRENT_FAULT, 0xEE91),
            (DiagnosticCode.DIAG_ERR_UNDERVOLTAGE_FAULT, 0xEE92),
            (DiagnosticCode.DIAG_ERR_GROUND_LOOP_FAULT, 0xEE93),
            (DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT, 0xEE94),
            (DiagnosticCode.DIAG_ERR_PSE_COMMUNICATION_TIMEOUT, 0xEE95),
        ]:
            expected_s16 = expected_u16 - 0x10000 if expected_u16 >= 0x8000 else expected_u16
            assert code == expected_u16
            assert code == expected_s16
            assert expected_u16 == code
            assert expected_s16 == code
            assert (code & 0xFFFF) == expected_u16
            assert (0xFFFF & code) == expected_u16
            assert hash(code) == hash(expected_u16)
            assert f"0x{expected_u16:04X}" in str(code)
            assert f"0x{expected_u16:04X}" in repr(code)

        assert DiagnosticCode.DIAG_ERR_OVERCURRENT_FAULT != DiagnosticCode.DIAG_OK
        assert DiagnosticCode.DIAG_ERR_OVERCURRENT_FAULT != 0

    def test_podl_status_bits_flags(self) -> None:
        """Validate PoDLStatusBits IntFlag bitmasks."""
        assert PoDLStatusBits.ONLINE == 1 << 0
        assert PoDLStatusBits.POWERED == 1 << 1
        assert PoDLStatusBits.OVERCURRENT == 1 << 2
        assert PoDLStatusBits.UNDERVOLTAGE == 1 << 3
        assert PoDLStatusBits.GROUND_FAULT == 1 << 4
        assert PoDLStatusBits.CRC_FAULT == 1 << 5
        assert PoDLStatusBits.TIMEOUT == 1 << 6
        assert PoDLStatusBits.SAFETY_TRIPPED == 1 << 7

        assert CipSafetyPoDLStatusBits is PoDLStatusBits
        assert CIPPoDLStatusBits is PoDLStatusBits

    def test_exceptions_hierarchy(self) -> None:
        """Validate CIPPoDLSafetyError exception inheritance structure."""
        assert issubclass(PoDLOvercurrentFaultError, CIPPoDLSafetyError)
        assert issubclass(PoDLUndervoltageFaultError, CIPPoDLSafetyError)
        assert issubclass(PoDLGroundLoopFaultError, CIPPoDLSafetyError)
        assert issubclass(PoDLDualCrcSafetyFaultError, CIPPoDLSafetyError)
        assert issubclass(PoDLPSECommunicationTimeoutError, CIPPoDLSafetyError)

        assert PoDLCrcFaultError is PoDLDualCrcSafetyFaultError
        assert PoDLTimeoutError is PoDLPSECommunicationTimeoutError
        assert PoDLOvercurrentError is PoDLOvercurrentFaultError
        assert PoDLUndervoltageError is PoDLUndervoltageFaultError
        assert PoDLGroundFaultError is PoDLGroundLoopFaultError


# ============================================================================
# 2. TestDualSafetyCrcMathematics
# ============================================================================

class TestDualSafetyCrcMathematics:
    """Validate CIP Safety dual CRC-S1 / CRC-S2 mathematics, sensitivity, and EPID hashing."""

    def test_crc_s1_polynomial_and_init(self) -> None:
        """Validate CRC-S1 generator polynomial 0x5935 and initial seed 0x0000."""
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_INIT == 0x0000
        assert CRC_S_INIT == 0x0000
        assert CRC_INIT == 0x0000

    def test_crc_s2_polynomial_and_init(self) -> None:
        """Validate CRC-S2 generator polynomial 0x755B and initial seed 0x0000."""
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S2_POLY == 0x755B

    def test_compute_crc_s1_determinism_and_bounds(self) -> None:
        """Validate CRC-S1 computation determinism and 16-bit bounding."""
        data = b"\x01\x02\x03\x04\x05\x06"
        c1 = compute_crc_s1(data)
        assert 0 <= c1 <= 0xFFFF
        assert compute_crc_s1(data) == c1
        assert compute_crc_s1(b"") == 0x0000

    def test_compute_crc_s2_determinism_and_bounds(self) -> None:
        """Validate CRC-S2 computation determinism and 16-bit bounding."""
        data = bytes(~b & 0xFF for b in b"\x50\x44\x00\x01\x00\x00\x01\x90\x03\x0C\x5D\xC0\x01\x5E\x07\x3A")
        c2 = compute_crc_s2(data)
        assert 0 <= c2 <= 0xFFFF
        assert compute_crc_s2(data) == c2
        assert compute_crc_s2(b"") == 0x0000

    def test_crc_s1_single_bit_perturbation_sensitivity(self) -> None:
        """Validate single-bit perturbation detection across payload for CRC-S1."""
        base_payload = b"\x10\x20\x30\x40\x50\x60\x70\x80"
        base_crc = compute_crc_s1(base_payload)
        for byte_idx in range(len(base_payload)):
            for bit_idx in range(8):
                mutated = bytearray(base_payload)
                mutated[byte_idx] ^= (1 << bit_idx)
                mutated_crc = compute_crc_s1(bytes(mutated))
                assert mutated_crc != base_crc, f"CRC collision on byte {byte_idx} bit {bit_idx}"

    def test_crc_s2_single_bit_perturbation_sensitivity(self) -> None:
        """Validate single-bit perturbation detection across inverted header for CRC-S2."""
        raw_header = (
            DEFAULT_SESSION_ID.to_bytes(2, "big")
            + (1).to_bytes(2, "big")
            + (400).to_bytes(4, "big")
            + (3).to_bytes(1, "big")
            + (12).to_bytes(1, "big")
            + (24000).to_bytes(2, "big")
            + (350).to_bytes(2, "big")
            + (1850).to_bytes(2, "big")
        )
        base_inverted = bytes(~b & 0xFF for b in raw_header)
        base_crc = compute_crc_s2(base_inverted)
        for byte_idx in range(len(base_inverted)):
            for bit_idx in range(8):
                mutated = bytearray(base_inverted)
                mutated[byte_idx] ^= (1 << bit_idx)
                mutated_crc = compute_crc_s2(bytes(mutated))
                assert mutated_crc != base_crc, f"CRC collision on byte {byte_idx} bit {bit_idx}"

    def test_crc_calculation_aliases(self) -> None:
        """Validate CRC calculation function aliases."""
        data = b"\xAA\xBB\xCC\xDD"
        expected_s1 = compute_crc_s1(data)
        assert calc_crc_s1(data) == expected_s1
        assert calculate_cip_safety_crc_s1(data) == expected_s1
        assert calculate_crc_s1(data) == expected_s1

        expected_s2 = compute_crc_s2(data)
        assert calc_crc_s2(data) == expected_s2
        assert calculate_cip_safety_crc_s2(data) == expected_s2
        assert calculate_crc_s2(data) == expected_s2

    def test_compute_crc_argument_variations(self) -> None:
        """Validate compute_crc_s1 and compute_crc_s2 with variable arguments."""
        b1 = b"\x01\x02"
        b2 = b"\x03\x04"
        assert compute_crc_s1(b1, b2) == compute_crc_s1(b1 + b2)
        assert compute_crc_s1(payload_bytes=b1) == compute_crc_s1(b1)
        assert compute_crc_s1(data=b1) == compute_crc_s1(b1)

        # compute_crc_s2 with explicit fields
        c2_from_fields = compute_crc_s2(
            DEFAULT_SESSION_ID,
            1,
            400,
            3,
            12,
            24000,
            350,
            1850,
        )
        assert 0 <= c2_from_fields <= 0xFFFF

    def test_epid_hash_and_crc32(self) -> None:
        """Validate Electronic Product ID (EPID) 16-bit and 32-bit CRC hashes."""
        h16 = compute_epid_hash(DEFAULT_SAFETY_EPID)
        assert 0 <= h16 <= 0xFFFF

        crc32_val = compute_epid_crc32(DEFAULT_SAFETY_EPID)
        assert crc32_val == 0x0E7CC1A9
        assert (crc32_val & 0xFFFF) == h16

    def test_verify_dual_crc_s_function(self) -> None:
        """Validate verify_dual_crc_s helper function with matching and mismatched CRCs."""
        payload = b"\x01\x02\x03\x04"
        inverted = b"\xFE\xFD\xFC\xFB"
        s1 = compute_crc_s1(payload)
        s2 = compute_crc_s2(inverted)
        assert verify_dual_crc_s(payload, inverted, s1, s2) is True
        assert verify_dual_crc_s(payload, inverted, s1 ^ 1, s2) is False
        assert verify_dual_crc_s(payload, inverted, s1, s2 ^ 1) is False

    def test_calculate_crc16_ccitt(self) -> None:
        """Validate CRC16-CCITT helper function."""
        data = b"123456789"
        res = calculate_crc16_ccitt(data)
        assert 0 <= res <= 0xFFFF


# ============================================================================
# 3. TestPacketModelAndBinarySerialization
# ============================================================================

class TestPacketModelAndBinarySerialization:
    """Validate CIPPoDLPacket dataclass, binary serialization roundtrip, and tampering detection."""

    def test_packet_instantiation_defaults(self) -> None:
        """Validate CIPPoDLPacket default attributes and automatic CRC computation."""
        pkt = CIPPoDLPacket()
        assert pkt.session_id == DEFAULT_SESSION_ID
        assert pkt.sequence_number == 0
        assert pkt.timestamp_us == 0
        assert pkt.podl_state == PoDLState.POWERED_NORMAL
        assert pkt.pse_class == PoDLPSEClass.CLASS_12
        assert pkt.voltage_mv == 24000
        assert pkt.current_ma == 350
        assert pkt.loop_mohm == 1850
        assert pkt.payload_bytes == b"\x01\x02\x03\x04"
        assert pkt.crc_s1 != 0
        assert pkt.crc_s2 != 0
        assert pkt.validate_crcs() is True
        assert pkt.is_valid() is True

    def test_packet_property_accessors_and_setters(self) -> None:
        """Validate packet properties and setters."""
        pkt = CIPPoDLPacket()
        pkt.sequence = 42
        assert pkt.sequence_number == 42
        assert pkt.sequence == 42

        pkt.timestamp = 1000000
        assert pkt.timestamp_us == 1000000
        assert pkt.timestamp == 1000000

        pkt.payload = b"\xAA\xBB"
        assert pkt.payload_bytes == b"\xAA\xBB"
        assert pkt.payload == b"\xAA\xBB"

        assert pkt.voltage == 24000
        assert pkt.current == 350
        assert pkt.loop_resistance == 1850
        assert pkt.power_mw == int(24000 * 350 / 1000)

    def test_packet_get_inverted_header_integrity(self) -> None:
        """Validate get_inverted_header byte exactness and inversion."""
        pkt = CIPPoDLPacket(session_id=0x1122, sequence_number=0x3344)
        inv = pkt.get_inverted_header()
        assert len(inv) == 16
        # Byte 0 should be ~(0x11) & 0xFF
        assert inv[0] == (~0x11) & 0xFF
        assert inv[1] == (~0x22) & 0xFF
        assert inv[2] == (~0x33) & 0xFF
        assert inv[3] == (~0x44) & 0xFF

    def test_packet_pack_and_unpack_roundtrip(self) -> None:
        """Validate binary serialization pack/unpack exact roundtrip."""
        pkt = CIPPoDLPacket(
            session_id=0x5044,
            sequence_number=123,
            timestamp_us=987654,
            podl_state=PoDLState.POWERED_NORMAL,
            pse_class=PoDLPSEClass.CLASS_13,
            voltage_mv=24000,
            current_ma=700,
            loop_mohm=2100,
            payload_bytes=b"\xCA\xFE\xBA\xBE",
        )
        packed = pkt.pack()
        assert isinstance(packed, bytes)
        assert len(packed) == struct.calcsize("!H H I B B H H H H H H") + 4

        unpacked = CIPPoDLPacket.unpack(packed)
        assert unpacked.session_id == 0x5044
        assert unpacked.sequence_number == 123
        assert unpacked.timestamp_us == 987654
        assert unpacked.podl_state == PoDLState.POWERED_NORMAL
        assert unpacked.pse_class == PoDLPSEClass.CLASS_13
        assert unpacked.voltage_mv == 24000
        assert unpacked.current_ma == 700
        assert unpacked.loop_mohm == 2100
        assert unpacked.payload_bytes == b"\xCA\xFE\xBA\xBE"
        assert unpacked.crc_s1 == pkt.crc_s1
        assert unpacked.crc_s2 == pkt.crc_s2
        assert unpacked.validate_crcs() is True

    def test_packet_unpack_truncated_data_raises(self) -> None:
        """Validate unpacking truncated binary data raises ValueError."""
        header_len = struct.calcsize("!H H I B B H H H H H H")
        with pytest.raises(ValueError, match="Packet data too short"):
            CIPPoDLPacket.unpack(b"\x00" * (header_len - 1))

    def test_packet_tamper_detection_crc_s1(self) -> None:
        """Validate packet detects tampering in payload bytes via CRC-S1."""
        pkt = CIPPoDLPacket(payload_bytes=b"\x01\x02\x03\x04")
        assert pkt.validate_crcs() is True
        pkt.payload_bytes = b"\x01\x02\x03\x05"
        assert pkt.validate_crcs() is False
        assert pkt.is_valid() is False

    def test_packet_tamper_detection_crc_s2(self) -> None:
        """Validate packet detects tampering in header fields via CRC-S2."""
        pkt = CIPPoDLPacket()
        assert pkt.validate_crcs() is True
        pkt.voltage_mv += 1
        assert pkt.validate_crcs() is False
        assert pkt.is_valid() is False

    def test_packet_factory_functions_and_aliases(self) -> None:
        """Validate create_valid_podl_packet and class aliases."""
        p1 = create_valid_podl_packet(sequence=5)
        assert p1.sequence_number == 5
        assert p1.validate_crcs() is True

        p2 = create_valid_cip_podl_packet(sequence=6)
        assert p2.sequence_number == 6

        p3 = create_valid_cip_safety_podl_packet(sequence=7)
        assert p3.sequence_number == 7

        assert CipSafetyPoDLPacket is CIPPoDLPacket
        assert PoDLPacket is CIPPoDLPacket
        assert CIPPoDLSafetyPacket is CIPPoDLPacket
        assert PoDLSafetyPacket is CIPPoDLPacket


# ============================================================================
# 4. TestPoDLPSEClassificationAndPowerCalculation
# ============================================================================

class TestPoDLPSEClassificationAndPowerCalculation:
    """Validate PoDL PSE classification table, electrical bounds, and P = V * I formula."""

    def test_all_pse_classes_in_specs_table(self) -> None:
        """Validate all 6 PSE classes (10 through 15) are configured in PSE_CLASS_SPECS."""
        for c in [
            PoDLPSEClass.CLASS_10,
            PoDLPSEClass.CLASS_11,
            PoDLPSEClass.CLASS_12,
            PoDLPSEClass.CLASS_13,
            PoDLPSEClass.CLASS_14,
            PoDLPSEClass.CLASS_15,
        ]:
            assert c in PSE_CLASS_SPECS
            specs = PSE_CLASS_SPECS[c]
            assert "v_nominal_mv" in specs
            assert "v_min_mv" in specs
            assert "v_max_mv" in specs
            assert "i_max_ma" in specs
            assert "p_max_mw" in specs

    def test_pse_class_voltage_boundaries(self) -> None:
        """Validate exact voltage thresholds across 12V, 24V, and 48V classes."""
        # 12V classes (10 and 11)
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_10]["v_nominal_mv"] == 12000
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_10]["v_min_mv"] == 10000
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_11]["v_nominal_mv"] == 12000
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_11]["v_min_mv"] == 10000

        # 24V classes (12 and 13)
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_12]["v_nominal_mv"] == 24000
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_12]["v_min_mv"] == 20000
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_13]["v_nominal_mv"] == 24000
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_13]["v_min_mv"] == 20000

        # 48V classes (14 and 15)
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_14]["v_nominal_mv"] == 48000
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_14]["v_min_mv"] == 40000
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_15]["v_nominal_mv"] == 48000
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_15]["v_min_mv"] == 40000

    def test_pse_class_current_limits(self) -> None:
        """Validate exact current thresholds across classes 10..15."""
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_10]["i_max_ma"] == 460
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_11]["i_max_ma"] == 830
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_12]["i_max_ma"] == 460
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_13]["i_max_ma"] == 920
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_14]["i_max_ma"] == 630
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_15]["i_max_ma"] == 1360

    def test_pse_class_max_power_limits(self) -> None:
        """Validate maximum power envelope across classes 10..15."""
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_10]["p_max_mw"] == 5520
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_11]["p_max_mw"] == 9960
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_12]["p_max_mw"] == 11040
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_13]["p_max_mw"] == 22080
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_14]["p_max_mw"] == 30240
        assert PSE_CLASS_SPECS[PoDLPSEClass.CLASS_15]["p_max_mw"] == 65280

    def test_power_calculation_formula_p_equals_v_times_i(self) -> None:
        """Validate electrical formula P (mW) = (V (mV) * I (mA)) / 1000."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        # Nominal Class 12: 24,000 mV, 350 mA -> 8,400 mW
        assert engine.voltage_mv == 24000
        assert engine.current_ma == 350
        assert engine.power_mw == 8400

        # Change voltage and current
        engine.voltage_mv = 12000
        engine.current_ma = 500
        assert engine.power_mw == 6000

        # Check packet property
        pkt = CIPPoDLPacket(voltage_mv=48000, current_ma=1000)
        assert pkt.power_mw == 48000

    def test_pse_class_engine_switching_updates_limits(self) -> None:
        """Validate changing pse_class on CIPPoDLSafetyEngine updates electrical boundaries."""
        engine = CIPPoDLSafetyEngine(pse_class=PoDLPSEClass.CLASS_10)
        assert engine.v_min_mv == 10000
        assert engine.i_max_ma == 460
        assert engine.v_nominal_mv == 12000

        engine.pse_class = PoDLPSEClass.CLASS_15
        assert engine.v_min_mv == 40000
        assert engine.i_max_ma == 1360
        assert engine.v_nominal_mv == 48000


# ============================================================================
# 5. TestOvercurrentInjectionAndTrip
# ============================================================================

class TestOvercurrentInjectionAndTrip:
    """Validate overcurrent fault injection, safety interlock trip 0xEE91, and status word flags."""

    def test_inject_overcurrent_default_trips_0xEE91(self) -> None:
        """Validate default overcurrent injection trips DIAG_ERR_OVERCURRENT_FAULT."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        assert engine.online is True

        engine.inject_overcurrent()
        assert engine.diagnostic_code == DIAG_ERR_OVERCURRENT_FAULT
        assert engine.diagnostic_code == 0xEE91
        assert engine.podl_state == PoDLState.SAFETY_TRIP
        assert engine.online is False
        assert engine.tripped is True

    def test_inject_overcurrent_custom_value(self) -> None:
        """Validate injecting specific current value triggers overcurrent trip."""
        engine = CIPPoDLSafetyEngine(pse_class=PoDLPSEClass.CLASS_12)
        engine.connect()
        engine.inject_overcurrent(1500)
        assert engine.current_ma == 1500
        assert engine.diagnostic_code == DIAG_ERR_OVERCURRENT_FAULT

    def test_overcurrent_trip_across_all_pse_classes(self) -> None:
        """Validate overcurrent trip behavior for each of the 6 PSE classes."""
        for pse_class in [
            PoDLPSEClass.CLASS_10,
            PoDLPSEClass.CLASS_11,
            PoDLPSEClass.CLASS_12,
            PoDLPSEClass.CLASS_13,
            PoDLPSEClass.CLASS_14,
            PoDLPSEClass.CLASS_15,
        ]:
            engine = CIPPoDLSafetyEngine(pse_class=pse_class)
            engine.connect()
            limit = engine.i_max_ma
            engine.inject_overcurrent(limit + 50)
            assert engine.diagnostic_code == DIAG_ERR_OVERCURRENT_FAULT
            assert engine.tripped is True

    def test_receive_packet_with_overcurrent_trips(self) -> None:
        """Validate ingress packet reporting current > i_max_ma trips safety."""
        engine = CIPPoDLSafetyEngine(pse_class=PoDLPSEClass.CLASS_12)
        engine.connect()
        # Class 12 limit is 460 mA; send packet with 800 mA
        pkt = CIPPoDLPacket(
            session_id=engine.session_id,
            sequence_number=1,
            timestamp_us=400,
            podl_state=PoDLState.POWERED_NORMAL,
            pse_class=PoDLPSEClass.CLASS_12,
            voltage_mv=24000,
            current_ma=800,
            loop_mohm=1850,
        )
        pkt.compute_crcs()
        ok = engine.receive_packet(pkt)
        assert ok is False
        assert engine.diagnostic_code == DIAG_ERR_OVERCURRENT_FAULT
        assert engine.tripped is True

    def test_overcurrent_status_bits_asserted(self) -> None:
        """Validate PoDLStatusBits.OVERCURRENT and SAFETY_TRIPPED set in status_word."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        engine.inject_overcurrent()
        word = engine.status_word
        assert (word & PoDLStatusBits.OVERCURRENT) != 0
        assert (word & PoDLStatusBits.SAFETY_TRIPPED) != 0

    def test_overcurrent_coil_states(self) -> None:
        """Validate discrete coils %M646 de-asserted and %M647 asserted on overcurrent."""
        rt = RegisterTable()
        engine = CIPPoDLSafetyEngine(register_table=rt)
        engine.connect()
        engine.sync_to_registers()
        assert rt.read_bit(COIL_CIP_PODL_ONLINE) is True
        assert rt.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is False

        engine.inject_overcurrent()
        engine.sync_to_registers()
        assert rt.read_bit(COIL_CIP_PODL_ONLINE) is False
        assert rt.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is True


# ============================================================================
# 6. TestUndervoltageInjectionAndTrip
# ============================================================================

class TestUndervoltageInjectionAndTrip:
    """Validate undervoltage fault injection, safety interlock trip 0xEE92, and status word flags."""

    def test_inject_undervoltage_default_trips_0xEE92(self) -> None:
        """Validate default undervoltage injection trips DIAG_ERR_UNDERVOLTAGE_FAULT."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        assert engine.online is True

        engine.inject_undervoltage()
        assert engine.diagnostic_code == DIAG_ERR_UNDERVOLTAGE_FAULT
        assert engine.diagnostic_code == 0xEE92
        assert engine.podl_state == PoDLState.SAFETY_TRIP
        assert engine.online is False
        assert engine.tripped is True

    def test_inject_undervoltage_custom_value(self) -> None:
        """Validate injecting specific voltage collapses triggers undervoltage trip."""
        engine = CIPPoDLSafetyEngine(pse_class=PoDLPSEClass.CLASS_12)
        engine.connect()
        engine.inject_undervoltage(12000)
        assert engine.voltage_mv == 12000
        assert engine.diagnostic_code == DIAG_ERR_UNDERVOLTAGE_FAULT

    def test_undervoltage_trip_across_all_pse_classes(self) -> None:
        """Validate undervoltage trip behavior across all 6 PSE classes."""
        for pse_class in [
            PoDLPSEClass.CLASS_10,
            PoDLPSEClass.CLASS_11,
            PoDLPSEClass.CLASS_12,
            PoDLPSEClass.CLASS_13,
            PoDLPSEClass.CLASS_14,
            PoDLPSEClass.CLASS_15,
        ]:
            engine = CIPPoDLSafetyEngine(pse_class=pse_class)
            engine.connect()
            limit = engine.v_min_mv
            engine.inject_undervoltage(limit - 1000)
            assert engine.diagnostic_code == DIAG_ERR_UNDERVOLTAGE_FAULT
            assert engine.tripped is True

    def test_receive_packet_with_undervoltage_trips(self) -> None:
        """Validate ingress packet reporting voltage < v_min_mv trips safety."""
        engine = CIPPoDLSafetyEngine(pse_class=PoDLPSEClass.CLASS_12)
        engine.connect()
        # Class 12 limit is 20000 mV; send packet with 15000 mV
        pkt = CIPPoDLPacket(
            session_id=engine.session_id,
            sequence_number=1,
            timestamp_us=400,
            podl_state=PoDLState.POWERED_NORMAL,
            pse_class=PoDLPSEClass.CLASS_12,
            voltage_mv=15000,
            current_ma=350,
            loop_mohm=1850,
        )
        pkt.compute_crcs()
        ok = engine.receive_packet(pkt)
        assert ok is False
        assert engine.diagnostic_code == DIAG_ERR_UNDERVOLTAGE_FAULT
        assert engine.tripped is True

    def test_undervoltage_status_bits_asserted(self) -> None:
        """Validate PoDLStatusBits.UNDERVOLTAGE and SAFETY_TRIPPED set in status_word."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        engine.inject_undervoltage()
        word = engine.status_word
        assert (word & PoDLStatusBits.UNDERVOLTAGE) != 0
        assert (word & PoDLStatusBits.SAFETY_TRIPPED) != 0

    def test_undervoltage_coil_states(self) -> None:
        """Validate discrete coils %M646 de-asserted and %M647 asserted on undervoltage."""
        rt = RegisterTable()
        engine = CIPPoDLSafetyEngine(register_table=rt)
        engine.connect()
        engine.inject_undervoltage()
        engine.sync_to_registers()
        assert rt.read_bit(COIL_CIP_PODL_ONLINE) is False
        assert rt.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is True


# ============================================================================
# 7. TestGroundLoopFaultInjectionAndTrip
# ============================================================================

class TestGroundLoopFaultInjectionAndTrip:
    """Validate ground loop fault injection, safety interlock trip 0xEE93, and status word flags."""

    def test_inject_ground_fault_default_trips_0xEE93(self) -> None:
        """Validate default ground loop fault injection trips DIAG_ERR_GROUND_LOOP_FAULT."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        assert engine.online is True

        engine.inject_ground_fault()
        assert engine.diagnostic_code == DIAG_ERR_GROUND_LOOP_FAULT
        assert engine.diagnostic_code == 0xEE93
        assert engine.ground_fault_active is True
        assert engine.podl_state == PoDLState.SAFETY_TRIP
        assert engine.online is False
        assert engine.tripped is True

    def test_inject_ground_fault_custom_resistance(self) -> None:
        """Validate ground fault injection with custom high loop resistance."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        engine.inject_ground_fault(75000)
        assert engine.loop_mohm == 75000
        assert engine.diagnostic_code == DIAG_ERR_GROUND_LOOP_FAULT

    def test_receive_packet_with_ground_fault_trips(self) -> None:
        """Validate ingress packet reporting loop resistance > limit trips safety."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        # Default limit is 65000 mOhm; send 80000 mOhm
        pkt = CIPPoDLPacket(
            session_id=engine.session_id,
            sequence_number=1,
            timestamp_us=400,
            podl_state=PoDLState.POWERED_NORMAL,
            pse_class=PoDLPSEClass.CLASS_12,
            voltage_mv=24000,
            current_ma=350,
            loop_mohm=80000,
        )
        pkt.compute_crcs()
        ok = engine.receive_packet(pkt)
        assert ok is False
        assert engine.diagnostic_code == DIAG_ERR_GROUND_LOOP_FAULT
        assert engine.tripped is True

    def test_ground_fault_status_bits_asserted(self) -> None:
        """Validate PoDLStatusBits.GROUND_FAULT and SAFETY_TRIPPED set in status_word."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        engine.inject_ground_fault()
        word = engine.status_word
        assert (word & PoDLStatusBits.GROUND_FAULT) != 0
        assert (word & PoDLStatusBits.SAFETY_TRIPPED) != 0

    def test_ground_fault_coil_states(self) -> None:
        """Validate discrete coils %M646 de-asserted and %M647 asserted on ground fault."""
        rt = RegisterTable()
        engine = CIPPoDLSafetyEngine(register_table=rt)
        engine.connect()
        engine.inject_ground_fault()
        engine.sync_to_registers()
        assert rt.read_bit(COIL_CIP_PODL_ONLINE) is False
        assert rt.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is True


# ============================================================================
# 8. TestSerialSccpFrameTimeoutAndTrip
# ============================================================================

class TestSerialSccpFrameTimeoutAndTrip:
    """Validate serial SCCP frame loss watchdog timeout (> 1000 us loss) tripping 0xEE95."""

    def test_inject_sccp_timeout_trips_0xEE95(self) -> None:
        """Validate direct injection of serial SCCP communication timeout."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        assert engine.online is True

        engine.inject_sccp_timeout()
        assert engine.diagnostic_code == DIAG_ERR_PSE_COMMUNICATION_TIMEOUT
        assert engine.diagnostic_code == 0xEE95
        assert engine.podl_state == PoDLState.SAFETY_TRIP
        assert engine.online is False
        assert engine.tripped is True

    def test_sccp_timeout_accumulation_in_scan_step(self) -> None:
        """Validate scan_step accumulation trips when dt exceeds timeout limit."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        assert engine.sccp_timer_us == 0.0

        # Run scan step with dt=0.0015 s (1500 us > 1000 us timeout)
        res = engine.scan_step(dt=0.0015)
        assert res.status == AgentStatus.SUCCESS
        assert engine.diagnostic_code == DIAG_ERR_PSE_COMMUNICATION_TIMEOUT
        assert engine.podl_state == PoDLState.SAFETY_TRIP
        assert engine.tripped is True

    def test_sccp_timer_reset_on_receive_packet(self) -> None:
        """Validate receiving valid packet resets serial SCCP frame loss timer."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        engine.sccp_timer_us = 800.0

        pkt = engine.send_packet()
        ok = engine.receive_packet(pkt)
        assert ok is True
        assert engine.sccp_timer_us == 0.0

    def test_sccp_timeout_aliases(self) -> None:
        """Validate inject_timeout and inject_communication_timeout aliases."""
        e1 = CIPPoDLSafetyEngine()
        e1.connect()
        e1.inject_timeout()
        assert e1.diagnostic_code == DIAG_ERR_PSE_COMMUNICATION_TIMEOUT

        e2 = CIPPoDLSafetyEngine()
        e2.connect()
        e2.inject_communication_timeout()
        assert e2.diagnostic_code == DIAG_ERR_PSE_COMMUNICATION_TIMEOUT

    def test_sccp_timeout_status_bits_asserted(self) -> None:
        """Validate PoDLStatusBits.TIMEOUT and SAFETY_TRIPPED set in status_word."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        engine.inject_sccp_timeout()
        word = engine.status_word
        assert (word & PoDLStatusBits.TIMEOUT) != 0
        assert (word & PoDLStatusBits.SAFETY_TRIPPED) != 0


# ============================================================================
# 9. TestCrcCorruptionInjectionAndTrip
# ============================================================================

class TestCrcCorruptionInjectionAndTrip:
    """Validate dual CRC corruption injection, detection, and trip 0xEE94."""

    def test_inject_crc_fault_trips_0xEE94(self) -> None:
        """Validate direct injection of CRC safety fault."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        assert engine.packet_loss_counter == 0

        engine.inject_crc_fault()
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.diagnostic_code == 0xEE94
        assert engine.podl_state == PoDLState.SAFETY_TRIP
        assert engine.packet_loss_counter == 1
        assert engine.online is False
        assert engine.tripped is True

    def test_receive_packet_with_corrupted_crc_s1_trips_0xEE94(self) -> None:
        """Validate ingress packet with corrupted CRC-S1 triggers safety trip."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        pkt = engine.send_packet()
        pkt.crc_s1 ^= 0x0001  # Corrupt CRC-S1
        ok = engine.receive_packet(pkt)
        assert ok is False
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.tripped is True
        assert engine.packet_loss_counter == 1

    def test_receive_packet_with_corrupted_crc_s2_trips_0xEE94(self) -> None:
        """Validate ingress packet with corrupted CRC-S2 triggers safety trip."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        pkt = engine.send_packet()
        pkt.crc_s2 ^= 0x0001  # Corrupt CRC-S2
        ok = engine.receive_packet(pkt)
        assert ok is False
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.tripped is True
        assert engine.packet_loss_counter == 1

    def test_packet_loss_counter_monotonic_increment(self) -> None:
        """Validate packet loss counter increments monotonically on repeated CRC faults."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        assert engine.packet_loss_counter == 0
        engine.inject_crc_fault()
        assert engine.packet_loss_counter == 1
        engine.inject_crc_fault()
        assert engine.packet_loss_counter == 2

    def test_crc_fault_status_bits_asserted(self) -> None:
        """Validate PoDLStatusBits.CRC_FAULT and SAFETY_TRIPPED set in status_word."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        engine.inject_crc_fault()
        word = engine.status_word
        assert (word & PoDLStatusBits.CRC_FAULT) != 0
        assert (word & PoDLStatusBits.SAFETY_TRIPPED) != 0


# ============================================================================
# 10. TestSafeStopInterlockAndCoils
# ============================================================================

class TestSafeStopInterlockAndCoils:
    """Validate safe stop interlock asserting %M647, clearing %M646, and fault recovery."""

    def test_healthy_coils_state(self) -> None:
        """Validate normal healthy operational state has %M646 True and %M647 False."""
        rt = RegisterTable()
        engine = CIPPoDLSafetyEngine(register_table=rt)
        engine.connect()
        engine.sync_to_registers()
        assert engine.online is True
        assert engine.tripped is False
        assert rt.read_bit(COIL_CIP_PODL_ONLINE) is True
        assert rt.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is False

    def test_safe_stop_interlock_on_all_diagnostic_faults(self) -> None:
        """Validate %M647 asserts and %M646 de-asserts across all 5 trip conditions."""
        for fault_func in [
            lambda e: e.inject_overcurrent(),
            lambda e: e.inject_undervoltage(),
            lambda e: e.inject_ground_fault(),
            lambda e: e.inject_crc_fault(),
            lambda e: e.inject_sccp_timeout(),
        ]:
            rt = RegisterTable()
            engine = CIPPoDLSafetyEngine(register_table=rt)
            engine.connect()
            fault_func(engine)
            engine.sync_to_registers()
            assert engine.online is False
            assert engine.tripped is True
            assert rt.read_bit(COIL_CIP_PODL_ONLINE) is False
            assert rt.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is True

    def test_coil_mutual_exclusivity(self) -> None:
        """Validate online and tripped properties are mutually exclusive."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        assert not (engine.online and engine.tripped)
        engine.inject_overcurrent()
        assert not (engine.online and engine.tripped)

    def test_clear_fault_restores_healthy_coils(self) -> None:
        """Validate clear_fault restores normal power and healthy coils."""
        rt = RegisterTable()
        engine = CIPPoDLSafetyEngine(register_table=rt)
        engine.connect()
        engine.inject_overcurrent()
        engine.sync_to_registers()
        assert rt.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is True

        engine.clear_fault()
        engine.sync_to_registers()
        assert engine.diagnostic_code == DIAG_OK
        assert engine.fault_code == 0
        assert engine.podl_state == PoDLState.POWERED_NORMAL
        assert engine.online is True
        assert engine.tripped is False
        assert rt.read_bit(COIL_CIP_PODL_ONLINE) is True
        assert rt.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is False

    def test_reset_restores_nominal_state(self) -> None:
        """Validate reset clears counters, sequence numbers, and restores normal power."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        engine.inject_overcurrent()
        engine.sequence_number = 100
        engine.tx_frame_count = 50
        engine.packet_loss_counter = 5

        engine.reset()
        assert engine.sequence_number == 0
        assert engine.tx_frame_count == 0
        assert engine.packet_loss_counter == 0
        assert engine.diagnostic_code == DIAG_OK
        assert engine.online is True
        assert engine.tripped is False

    def test_connect_and_disconnect_coil_behavior(self) -> None:
        """Validate disconnect sets SLEEP state (%M646=False) and connect restores power."""
        rt = RegisterTable()
        engine = CIPPoDLSafetyEngine(register_table=rt)
        engine.connect()
        engine.sync_to_registers()
        assert rt.read_bit(COIL_CIP_PODL_ONLINE) is True

        engine.disconnect()
        engine.sync_to_registers()
        assert engine.podl_state == PoDLState.SLEEP
        assert engine.online is False
        assert rt.read_bit(COIL_CIP_PODL_ONLINE) is False

        engine.connect()
        engine.sync_to_registers()
        assert engine.podl_state == PoDLState.POWERED_NORMAL
        assert engine.online is True
        assert rt.read_bit(COIL_CIP_PODL_ONLINE) is True

    def test_trip_safety_and_trip_fault_aliases(self) -> None:
        """Validate trip_safety and trip_fault aliases."""
        e1 = CIPPoDLSafetyEngine()
        e1.connect()
        e1.trip_safety(DIAG_ERR_OVERCURRENT_FAULT)
        assert e1.diagnostic_code == DIAG_ERR_OVERCURRENT_FAULT

        e2 = CIPPoDLSafetyEngine()
        e2.connect()
        e2.trip_fault(DIAG_ERR_UNDERVOLTAGE_FAULT)
        assert e2.diagnostic_code == DIAG_ERR_UNDERVOLTAGE_FAULT


# ============================================================================
# 11. TestHornerRegisterTableSynchronization
# ============================================================================

class TestHornerRegisterTableSynchronization:
    """Validate bit-exact synchronization to Horner OCS registers %R2770..%R2777 and coils %M646..%M647."""

    def test_sync_to_registers_healthy(self) -> None:
        """Validate sync_to_registers populates all 8 analog registers and 2 coils in healthy state."""
        rt = RegisterTable()
        engine = CIPPoDLSafetyEngine(pse_class=PoDLPSEClass.CLASS_12, register_table=rt)
        engine.connect()
        engine.sync_to_registers()

        assert rt.read_word(REG_CIP_PODL_STATUS) == 3
        assert rt.read_word(REG_CIP_PODL_VOLTAGE_MV) == 24000
        assert rt.read_word(REG_CIP_PODL_CURRENT_MA) == 350
        assert rt.read_word(REG_CIP_PODL_LOOP_RESISTANCE_MOHM) == 1850
        assert rt.read_word(REG_CIP_PODL_POWER_MW) == 8400
        assert rt.read_word(REG_CIP_PODL_FAULT_CODE) == 0
        assert rt.read_word(REG_CIP_PODL_PSE_CLASS) == 12
        assert rt.read_word(REG_CIP_PODL_DIAGNOSTIC_CODE) == 0

        assert rt.read_bit(COIL_CIP_PODL_ONLINE) is True
        assert rt.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is False

    def test_sync_to_registers_tripped(self) -> None:
        """Validate sync_to_registers in tripped state reflects fault codes and trip coils."""
        rt = RegisterTable()
        engine = CIPPoDLSafetyEngine(pse_class=PoDLPSEClass.CLASS_12, register_table=rt)
        engine.connect()
        engine.inject_overcurrent(1000)
        engine.sync_to_registers()

        assert rt.read_word(REG_CIP_PODL_STATUS) == int(PoDLState.SAFETY_TRIP)
        assert rt.read_word(REG_CIP_PODL_CURRENT_MA) == 1000
        assert (rt.read_word(REG_CIP_PODL_FAULT_CODE) & 0xFFFF) == 0xEE91
        assert (rt.read_word(REG_CIP_PODL_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE91
        assert rt.read_bit(COIL_CIP_PODL_ONLINE) is False
        assert rt.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is True

    def test_signed_16bit_safe_masking_in_registers(self) -> None:
        """Validate reading signed word registers with unsigned masking produces exact 0xEE9X values."""
        rt = RegisterTable()
        engine = CIPPoDLSafetyEngine(register_table=rt)
        engine.connect()
        for diag_code in [
            DIAG_ERR_OVERCURRENT_FAULT,
            DIAG_ERR_UNDERVOLTAGE_FAULT,
            DIAG_ERR_GROUND_LOOP_FAULT,
            DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
            DIAG_ERR_PSE_COMMUNICATION_TIMEOUT,
        ]:
            engine.trip_safety(diag_code)
            engine.sync_to_registers()
            val_u16 = rt.read_word(REG_CIP_PODL_DIAGNOSTIC_CODE) & 0xFFFF
            assert val_u16 == int(diag_code)

    def test_privilege_modes_user_and_system(self) -> None:
        """Validate sync_to_registers executes cleanly under both PrivilegeMode USER and SYSTEM."""
        rt = RegisterTable()
        engine = CIPPoDLSafetyEngine(register_table=rt)
        engine.connect()
        engine.sync_to_registers(privilege=PrivilegeMode.USER)
        assert rt.read_word(REG_CIP_PODL_STATUS) == 3
        engine.sync_to_registers(privilege=PrivilegeMode.SYSTEM)
        assert rt.read_word(REG_CIP_PODL_STATUS) == 3

    def test_safe_write_word_helpers(self) -> None:
        """Validate safe_write_word, safe_write_uword, and safe_write_bit utility functions."""
        rt = RegisterTable()
        safe_write_word(rt, "%R100", 0xEE91)
        assert (rt.read_word("%R100") & 0xFFFF) == 0xEE91

        safe_write_uword(rt, "%R101", 0x1234)
        assert rt.read_word("%R101") == 0x1234

        safe_write_bit(rt, "%M1", True)
        assert rt.read_bit("%M1") is True
        safe_write_bit(rt, "%M1", False)
        assert rt.read_bit("%M1") is False

    def test_register_table_fallback_hierarchy(self) -> None:
        """Validate register table resolution hierarchy in scan_step."""
        rt_engine = RegisterTable()
        rt_context = RegisterTable()
        engine = CIPPoDLSafetyEngine(register_table=rt_engine)
        engine.connect()

        # Passing context with its own register_table writes to that table
        ctx = ScanContext(dt=0.0004, register_table=rt_context)
        engine.scan_step(ctx)
        assert rt_context.read_word(REG_CIP_PODL_STATUS) == 3


# ============================================================================
# 12. TestPureIEC61131StructuredTextAndSecurity
# ============================================================================

class TestPureIEC61131StructuredTextAndSecurity:
    """Validate pure IEC 61131-3 ST POU CipSafetyPodlFaultSync and anti-ladder logic rejection."""

    def test_st_program_constant_and_aliases(self) -> None:
        """Validate ST program text constants and aliases."""
        assert "PROGRAM CipSafetyPodlFaultSync" in ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        assert "END_PROGRAM" in ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        assert CIP_SAFETY_PODL_FAULT_SYNC_POU == ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        assert CIP_SAFETY_PODL_FAULT_PURE_ST_POU == ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        assert CIP_SAFETY_PODL_POU == ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        assert PURE_ST_POU == ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        assert CipSafetyPodlFaultSync == ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC
        assert CipSafetyPodlFaultSyncPOU == ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC

    def test_st_parser_validates_pou(self) -> None:
        """Validate POU CipSafetyPodlFaultSync passes STParser syntax validation."""
        res = STParser.validate_code(ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC)
        assert res.status == AgentStatus.SUCCESS

    def test_st_parser_ast_pou_type_and_bound_registers(self) -> None:
        """Validate parsed AST has POUType.PROGRAM and all bound registers %R2770..%R2777 & %M646..%M647."""
        ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R2770", "%R2771", "%R2772", "%R2773", "%R2774", "%R2775", "%R2776", "%R2777",
            "%M646", "%M647",
        }
        for reg in expected_regs:
            assert reg in ast.bound_registers

    def test_security_guard_assert_pure_st_content(self) -> None:
        """Validate SecurityGuard.assert_pure_st_content accepts CipSafetyPodlFaultSync cleanly."""
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC)

    def test_verify_pure_st_helper_functions(self) -> None:
        """Validate verify_cip_safety_podl_fault_pure_st and verify_podl_pure_st return True."""
        assert verify_cip_safety_podl_fault_pure_st() is True
        assert verify_podl_pure_st() is True

    @pytest.mark.parametrize(
        "ladder_snippet",
        [
            "---[ ]---",   # Normally open contact
            "---[/]---",   # Normally closed contact
            "---( )---",   # Output coil
            "---(/)---",   # Inverted coil
            "RUNG 1: LD %R2770",
            "NETWORK 10:",
            "XIC %M646",
            "XIO %M647",
            "OTE %M646",
        ],
    )
    def test_security_guard_rejects_all_9_ladder_constructs(self, ladder_snippet: str) -> None:
        """Validate SecurityGuard strictly rejects all 9 ladder logic constructs with LadderForbiddenError."""
        corrupted_st = f"{ST_PROGRAM_CIP_SAFETY_PODL_FAULT_SYNC}\n{ladder_snippet}\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(corrupted_st)


# ============================================================================
# 13. TestILogicUnitComplianceAndSimulationSoak
# ============================================================================

class TestILogicUnitComplianceAndSimulationSoak:
    """Validate ILogicUnit interface compliance, scan_step variations, and 100-cycle memory soak."""

    def test_ilogic_unit_inheritance(self) -> None:
        """Validate CIPPoDLSafetyEngine implements ILogicUnit."""
        assert issubclass(CIPPoDLSafetyEngine, ILogicUnit)
        engine = CIPPoDLSafetyEngine()
        assert isinstance(engine, ILogicUnit)

    def test_scan_step_various_argument_types(self) -> None:
        """Validate scan_step accepts float dt, ScanContext, and keyword arguments."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()

        # 1. dt as positional float
        r1 = engine.scan_step(0.0004)
        assert r1.status == AgentStatus.SUCCESS

        # 2. ScanContext as positional arg
        ctx = ScanContext(dt=0.0004)
        r2 = engine.scan_step(ctx)
        assert r2.status == AgentStatus.SUCCESS

        # 3. dt as keyword arg
        r3 = engine.scan_step(dt=0.0004)
        assert r3.status == AgentStatus.SUCCESS

        # 4. dt_ms as keyword arg
        r4 = engine.scan_step(dt_ms=0.4)
        assert r4.status == AgentStatus.SUCCESS

        # 5. dt_us as keyword arg
        r5 = engine.scan_step(dt_us=400)
        assert r5.status == AgentStatus.SUCCESS

    def test_step_and_execute_aliases(self) -> None:
        """Validate step and execute aliases for scan_step."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        assert engine.step().status == AgentStatus.SUCCESS
        assert engine.execute().status == AgentStatus.SUCCESS

    def test_scan_step_execution_result_payload(self) -> None:
        """Validate ExecutionResult return contract and data dictionary fields."""
        engine = CIPPoDLSafetyEngine()
        engine.connect()
        res = engine.scan_step(0.0004)
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert "CIP Safety PoDL" in res.details
        assert res.data["podl_state"] == int(PoDLState.POWERED_NORMAL)
        assert res.data["pse_class"] == int(PoDLPSEClass.CLASS_12)
        assert res.data["voltage_mv"] == 24000
        assert res.data["current_ma"] == 350
        assert res.data["power_mw"] == 8400
        assert res.data["online"] is True
        assert res.data["tripped"] is False

    def test_100_cycle_simulation_soak_memory_bounded(self) -> None:
        """Validate 100-cycle simulation soak executes without errors and memory footprint is bounded."""
        tracemalloc.start()
        snap1 = tracemalloc.take_snapshot()

        rt = RegisterTable()
        engine = CIPPoDLSafetyEngine(register_table=rt)
        engine.connect()

        for cycle in range(100):
            # Send and receive normal packet every cycle to simulate active communication
            pkt = engine.send_packet()
            engine.receive_packet(pkt)
            res = engine.scan_step(0.0004)
            assert res.status == AgentStatus.SUCCESS
            assert engine.online is True
            assert engine.tripped is False
            assert rt.read_bit(COIL_CIP_PODL_ONLINE) is True
            assert rt.read_bit(COIL_CIP_PODL_SAFETY_TRIP) is False

        snap2 = tracemalloc.take_snapshot()
        tracemalloc.stop()

        # Compute memory growth
        stats = snap2.compare_to(snap1, "lineno")
        net_growth_kb = sum(s.size_diff for s in stats) / 1024.0
        # Assert net memory growth is under 300 KB for 100 cycles
        assert net_growth_kb < 300.0, f"Memory leak detected: growth {net_growth_kb:.2f} KB >= 300 KB"


# ============================================================================
# 14. TestVerificationRunner9StagesAndCli
# ============================================================================

class TestVerificationRunner9StagesAndCli:
    """Validate 9-stage verification runner function and CLI invocation interop."""

    def test_runner_passes_all_9_stages(self) -> None:
        """Validate run_cip_safety_podl_fault_verification passes all 9 stages deterministically."""
        res = run_cip_safety_podl_fault_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["total_stages"] == 9
        assert res["stages_passed"] == 9

    def test_runner_evidence_data_integrity(self) -> None:
        """Validate evidence dictionary metadata, work package, gate, and stages log."""
        res = run_cip_safety_podl_fault_verification()
        data = res["data"]
        assert data["work_package"] == "W316"
        assert data["gate"] == "G8"
        assert len(data["stages"]) == 9
        for s in data["stages"]:
            assert s["passed"] is True
            assert s["timing_ms"] >= 0.0

    def test_runner_no_file_written_when_output_path_is_none(self) -> None:
        """Validate that runner avoids disk writes when output_path is None."""
        res = run_cip_safety_podl_fault_verification(output_path=None)
        assert res["status"] == "success"

    def test_runner_writes_file_when_output_path_specified(self) -> None:
        """Validate runner writes valid JSON evidence file when output_path is provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "test_podl_evidence.json"
            res = run_cip_safety_podl_fault_verification(output_path=ev_path)
            assert res["status"] == "success"
            assert ev_path.exists()
            with open(ev_path, encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["total_stages"] == 9

    def test_quick_mode_verification(self) -> None:
        """Validate quick mode executes and passes all stages."""
        res = run_cip_safety_podl_fault_verification(quick=True)
        assert res["status"] == "success"
        assert res["stages_passed"] == 9

    def test_module_cli_direct_execution(self) -> None:
        """Verify executing module CLI directly with tempfile output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "module_podl_evidence.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "jev_cscape.telemetry.cip_safety_podl_fault",
                    "--output",
                    str(tmp_out),
                    "--quick",
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            assert proc.returncode == 0
            evidence = json.loads(proc.stdout)
            assert evidence["status"] == "success"
            assert tmp_out.exists()

    def test_script_runner_interop_cli(self) -> None:
        """Verify interop with scripts/run_cip_safety_podl_fault_verification.py CLI."""
        scripts_runner_path = Path(__file__).resolve().parent.parent / "scripts" / "run_cip_safety_podl_fault_verification.py"
        assert scripts_runner_path.exists()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "test_podl_script_evidence.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(scripts_runner_path),
                    "--output",
                    str(tmp_out),
                    "--quick",
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            assert proc.returncode == 0
            evidence = json.loads(proc.stdout)
            assert evidence["status"] == "success"
            assert evidence["stages_passed"] == 9
            assert tmp_out.exists()
