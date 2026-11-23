"""Comprehensive Unit Test Suite for Wave W301 CIP Safety Over PROFINET / PROFIsafe Gateway Bridge.

Work Package: W301 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Standards: ODVA CIP Safety Volume 5 (IEC 61784-3-2 / IEC 61508 SIL 3), PI PROFIsafe Profile (IEC 61784-3-3 / IEC 61508 SIL 3).

Covers Comprehensive Deterministic Unit Tests across 12 Mandatory Test Classes (70+ Tests):
1. TestConstantsEnumsAndDiagnosticCodes: Protocol constants, register mappings (%R2620..%R2627),
   discrete coils (%M611..%M612), extended aliases, diagnostic codes (0x0000, 0xEE41..0xEE46),
   signed/unsigned 16-bit representations, bitwise behavior, GatewayState and BridgeMode enums,
   CipSafetyProfisafeStatusBits, and protocol exceptions hierarchy.
2. TestCrcAlgorithms: CIP Safety dual CRCs (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B inverted header)
   and PROFIsafe F-CRC (32-bit poly 0x1EDC6F41, 24-bit poly 0x5D45, 16-bit poly 0x1021),
   determinism, bounds, single-bit flip sensitivity, and parameter validation.
3. TestFrameModels: CipSafetyFrame and ProfisafeFrame models, CRC generation and validation,
   payload corruption mutation, CRC mutation, binary serialization and deserialization bit-exact round-trip,
   and truncated payload error handling.
4. TestGatewayStateTransitions: State machine transitions (INIT -> CONNECTING -> RUNNING -> SAFETY_TRIP),
   connect(), complete_connection(), disconnect(), trip_fail_safe(), clear_faults(),
   feed_heartbeat(), and watchdog timeout surveillance.
5. TestBidirectionalTranslationMapping: CIP Safety -> PROFIsafe and PROFIsafe -> CIP Safety translation,
   bit-exact payload preservation, counter tracking, fail-safe substitution, and helper methods.
6. TestLatencyMeasurementAndThresholds: Forwarding translation latency tracking, nominal vs simulated latencies,
   latency exceeding safe threshold (> 5000 us) tripping 0xEE43, and recovery.
7. TestDiagnosticCodesAndFailSafeTrips: Verification of all diagnostic codes (0xEE41 through 0xEE46),
   fail-safe trip conditions, status bit assertion, and error count increments.
8. TestHornerRegisterTableSync: Bit-exact synchronization to Horner OCS analog registers (%R2620..%R2627)
   and discrete coils (%M611..%M612), signed 16-bit masking `(rt.read_word(...) & 0xFFFF) == expected`,
   bit-packing, and privilege modes.
9. TestILogicUnitCompliance: ILogicUnit interface compliance (scan_step with args/kwargs, step, execute, reset),
   name, priority, is_enabled properties, ScanContext and RegisterTable hierarchy, and ExecutionResult contracts.
10. TestPureIEC61131StructuredTextAndSecurity: Pure IEC 61131-3 Structured Text POU CipSafetyProfisafeBridgeSync
    validation via STParser and SecurityGuard, variable address bindings, and strict rejection of ladder logic
    constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
11. TestMultiCycleSoakAndStability: 100-cycle continuous scan soak test with zero fault trips, 100% SUCCESS outcomes,
    monotonic counter increments, and stable memory footprint verified via tracemalloc.
12. TestNineStageVerificationRunner: Complete 9-stage verification suite run_cip_safety_profisafe_verification,
    strict 4-state engineering contract validation, stage timing metrics, and JSON evidence emission.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import tracemalloc
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_profisafe import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_PROFISAFE_BRIDGE_CLASS_ID,
    CIP_SAFETY_PROFISAFE_GATEWAY_CLASS_ID,
    CIP_PROFISAFE_GATEWAY_CLASS_ID,
    CIP_PROFISAFE_BRIDGE_CLASS_ID,
    DEFAULT_SAFETY_NETWORK_NUMBER,
    DEFAULT_SNN,
    DEFAULT_F_DEST_ADDR,
    DEFAULT_F_SRC_ADDR,
    DEFAULT_F_DEST_ADD,
    DEFAULT_F_SOURCE_ADD,
    DEFAULT_F_SIL,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    DEFAULT_TRANSLATION_LATENCY_US,
    DEFAULT_NOMINAL_LATENCY_US,
    DEFAULT_MAX_FORWARDING_LATENCY_US,
    MAX_ALLOWED_TRANSLATION_LATENCY_US,
    MAX_FORWARDING_LATENCY_US,
    MAX_FAILSAFE_REACTION_TIME_MS,
    LATENCY_WATCHDOG_THRESHOLD_MS,
    DEFAULT_THROUGHPUT_FPS,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CRC_INIT,
    PROFISAFE_F_CRC_32_POLY,
    PROFISAFE_F_CRC_24_POLY,
    PROFISAFE_F_CRC_16_POLY,
    PROFISAFE_F_CRC_INIT,
    F_CRC_32_POLY,
    F_CRC_24_POLY,
    F_CRC_16_POLY,
    F_CRC_POLY,
    F_CRC_INIT,
    REG_CIP_PROFISAFE_STATUS,
    REG_CIP_PROFISAFE_CIP_SEQUENCE,
    REG_CIP_PROFISAFE_PROFISAFE_COUNTER,
    REG_CIP_PROFISAFE_TRANSLATION_LATENCY_US,
    REG_CIP_PROFISAFE_STATUS_WORD,
    REG_CIP_PROFISAFE_DIAGNOSTIC_CODE,
    REG_CIP_PROFISAFE_ERROR_COUNT,
    REG_CIP_PROFISAFE_THROUGHPUT_FPS,
    REG_CIP_PROFISAFE_STATE,
    REG_BRIDGE_STATUS,
    REG_CIP_PROFISAFE_GATEWAY_STATUS,
    REG_GATEWAY_STATUS_WORD,
    REG_GATEWAY_LATENCY_US,
    REG_CIP_PROFISAFE_LATENCY_US,
    REG_CIP_PROFISAFE_CIP_SEQ,
    REG_CIP_SEQUENCE_COUNTER,
    REG_CIP_SEQUENCE,
    REG_CIP_PROFISAFE_CONSEC_NO,
    REG_PROFISAFE_CONSEC_NO,
    REG_PROFISAFE_COUNTER,
    REG_TRANSLATION_LATENCY_US,
    REG_STATUS_WORD,
    REG_GATEWAY_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_CODE,
    REG_GATEWAY_ERROR_COUNT,
    REG_ERROR_COUNT,
    REG_THROUGHPUT_FPS,
    REG_FORWARDED_CIP_COUNT,
    REG_FORWARDED_PROFISAFE_COUNT,
    REG_CIP_PROFISAFE_CIP_TO_PROFISAFE_COUNT,
    REG_CIP_PROFISAFE_PROFISAFE_TO_CIP_COUNT,
    COIL_CIP_PROFISAFE_BRIDGE_ONLINE,
    COIL_CIP_PROFISAFE_SAFETY_TRIP,
    COIL_BRIDGE_ONLINE,
    COIL_SAFETY_TRIP,
    COIL_CIP_PROFISAFE_ONLINE,
    COIL_CIP_PROFISAFE_HEALTHY,
    COIL_CIP_PROFISAFE_TRIP,
    COIL_CIP_PROFISAFE_GATEWAY_HEALTHY,
    COIL_CIP_PROFISAFE_GATEWAY_TRIP,
    COIL_GATEWAY_HEALTHY,
    COIL_GATEWAY_TRIP,
    COIL_CIP_SAFETY_PROFISAFE_HEALTHY,
    COIL_CIP_SAFETY_PROFISAFE_TRIP,
    DiagnosticCode,
    DIAG_OK,
    DIAG_ERR_CIP_SAFETY_CRC,
    DIAG_ERR_PROFISAFE_CRC,
    DIAG_ERR_GATEWAY_LATENCY_EXCEEDED,
    DIAG_ERR_WATCHDOG_TIMEOUT,
    DIAG_ERR_F_STATUS_FAULT,
    DIAG_ERR_SNN_MISMATCH,
    DIAG_ERR_TIMEOUT,
    DIAG_ERR_SEQUENCE_MISMATCH,
    DIAG_ERR_LATENCY_EXCEEDED,
    DIAG_ERR_TRANSLATION_FAULT,
    DIAG_CIP_SAFETY_CRC,
    DIAG_CIP_CRC_FAULT,
    DIAG_CIP_CRC_ERROR,
    DIAG_ERR_CRC_S1_S2,
    DIAG_PROFISAFE_CRC,
    DIAG_PROFISAFE_CRC_FAULT,
    DIAG_PROFISAFE_CRC_ERROR,
    DIAG_ERR_F_CRC,
    DIAG_WATCHDOG_TIMEOUT,
    DIAG_PACKET_TIMEOUT,
    DIAG_SEQUENCE_MISMATCH,
    DIAG_SEQUENCE_FAULT,
    DIAG_SEQUENCE_ERROR,
    DIAG_ERR_F_CONSEC_NO,
    DIAG_LATENCY_EXCEEDED,
    DIAG_LATENCY_FAULT,
    DIAG_FORWARDING_LATENCY,
    DIAG_ERR_FORWARDING_LATENCY,
    DIAG_TRANSLATION_FAULT,
    DIAG_MAPPING_FAULT,
    DIAG_MAPPING_ERROR,
    DIAG_ERR_MAPPING_MISMATCH,
    CipSafetyProfisafeDiagnosticCode,
    ProfisafeGatewayDiagnosticCode,
    ProfisafeDiagnosticCode,
    GatewayDiagnosticCode,
    GatewayState,
    CipSafetyProfisafeState,
    ProfisafeGatewayState,
    BridgeState,
    SafetyGatewayState,
    GatewayBridgeState,
    BridgeMode,
    CipSafetyProfisafeMode,
    CipSafetyProfisafeStatusBits,
    ProfisafeGatewayStatusBits,
    GatewayStatusBits,
    CipSafetyProfisafeError,
    CipSafetyCrcError,
    ProfisafeCrcError,
    GatewayLatencyExceededError,
    GatewayWatchdogTimeoutError,
    ProfisafeFStatusFaultError,
    CipSafetySnnMismatchError,
    GatewayTimeoutError,
    GatewaySequenceError,
    GatewayLatencyError,
    GatewayTranslationError,
    calculate_cip_safety_crc_s1,
    calculate_cip_safety_crc_s2,
    calculate_crc_s1,
    calculate_crc_s2,
    compute_crc_s1,
    compute_crc_s2,
    calculate_profisafe_f_crc32,
    calculate_profisafe_f_crc24,
    calculate_profisafe_f_crc,
    calculate_fcrc,
    compute_fcrc,
    calculate_profisafe_fcrc,
    compute_profisafe_fcrc,
    calculate_profisafe_crc,
    compute_profisafe_crc,
    calculate_profisafe_fcrc16,
    CipSafetyFrame,
    ProfisafeFrame,
    ST_PROGRAM_CIP_SAFETY_PROFISAFE_BRIDGE_SYNC,
    ST_PROGRAM_CIP_SAFETY_PROFISAFE_SYNC,
    CIP_SAFETY_PROFISAFE_PURE_ST_POU,
    CIP_SAFETY_PROFISAFE_SYNC_POU,
    CipSafetyProfisafeBridgeSync,
    CipSafetyProfisafeSync,
    verify_cip_safety_profisafe_pure_st,
    CipSafetyProfisafeBridgeEngine,
    CipSafetyProfisafeEngine,
    CIPSafetyProfisafeBridgeEngine,
    CIPSafetyProfisafeEngine,
    ProfisafeBridgeEngine,
    CipSafetyProfisafeGateway,
    CIPSafetyProfisafeGateway,
    ProfisafeGatewayEngine,
    run_cip_safety_profisafe_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnosticCodes
# ============================================================================

class TestConstantsEnumsAndDiagnosticCodes:
    """Validate protocol constants, register mappings, diagnostic codes, and enums."""

    def test_protocol_class_ids_and_defaults(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_PROFISAFE_BRIDGE_CLASS_ID == 0x48
        assert CIP_SAFETY_PROFISAFE_GATEWAY_CLASS_ID == 0x4B
        assert CIP_PROFISAFE_GATEWAY_CLASS_ID == 0x4B
        assert CIP_PROFISAFE_BRIDGE_CLASS_ID == 0x48
        assert DEFAULT_SAFETY_NETWORK_NUMBER == 0x1A2B
        assert DEFAULT_SNN == 0x1A2B
        assert DEFAULT_F_SOURCE_ADD == 1
        assert DEFAULT_F_SRC_ADDR == 1
        assert DEFAULT_F_DEST_ADD == 2
        assert DEFAULT_F_DEST_ADDR == 2
        assert DEFAULT_F_SIL == 3
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 200.0
        assert DEFAULT_TRANSLATION_LATENCY_US == 350
        assert DEFAULT_MAX_FORWARDING_LATENCY_US == 5000.0
        assert MAX_ALLOWED_TRANSLATION_LATENCY_US == 5000
        assert MAX_FORWARDING_LATENCY_US == 5000.0
        assert MAX_FAILSAFE_REACTION_TIME_MS == 5.0
        assert LATENCY_WATCHDOG_THRESHOLD_MS == 5.0
        assert DEFAULT_THROUGHPUT_FPS == 100

    def test_register_and_coil_mappings(self) -> None:
        assert REG_CIP_PROFISAFE_STATUS == "%R2620"
        assert REG_CIP_PROFISAFE_CIP_SEQUENCE == "%R2621"
        assert REG_CIP_PROFISAFE_PROFISAFE_COUNTER == "%R2622"
        assert REG_CIP_PROFISAFE_TRANSLATION_LATENCY_US == "%R2623"
        assert REG_CIP_PROFISAFE_STATUS_WORD == "%R2624"
        assert REG_CIP_PROFISAFE_DIAGNOSTIC_CODE == "%R2625"
        assert REG_CIP_PROFISAFE_ERROR_COUNT == "%R2626"
        assert REG_CIP_PROFISAFE_THROUGHPUT_FPS == "%R2627"

        assert COIL_CIP_PROFISAFE_BRIDGE_ONLINE == "%M611"
        assert COIL_CIP_PROFISAFE_SAFETY_TRIP == "%M612"

    def test_extended_register_and_coil_aliases(self) -> None:
        assert REG_CIP_PROFISAFE_STATE == "%R2620"
        assert REG_BRIDGE_STATUS == "%R2620"
        assert REG_CIP_PROFISAFE_GATEWAY_STATUS == "%R2620"
        assert REG_CIP_SEQUENCE_COUNTER == "%R2621"
        assert REG_CIP_SEQUENCE == "%R2621"
        assert REG_CIP_PROFISAFE_CIP_SEQ == "%R2621"
        assert REG_CIP_PROFISAFE_CONSEC_NO == "%R2622"
        assert REG_PROFISAFE_CONSEC_NO == "%R2622"
        assert REG_PROFISAFE_COUNTER == "%R2622"
        assert REG_TRANSLATION_LATENCY_US == "%R2623"
        assert REG_CIP_PROFISAFE_LATENCY_US == "%R2623"
        assert REG_STATUS_WORD == "%R2624"
        assert REG_GATEWAY_STATUS_WORD == "%R2624"
        assert REG_DIAGNOSTIC_CODE == "%R2625"
        assert REG_GATEWAY_DIAGNOSTIC_CODE == "%R2625"
        assert REG_ERROR_COUNT == "%R2626"
        assert REG_GATEWAY_ERROR_COUNT == "%R2626"
        assert REG_THROUGHPUT_FPS == "%R2627"

        assert COIL_BRIDGE_ONLINE == "%M611"
        assert COIL_SAFETY_TRIP == "%M612"
        assert COIL_CIP_PROFISAFE_ONLINE == "%M611"
        assert COIL_CIP_PROFISAFE_HEALTHY == "%M611"
        assert COIL_CIP_PROFISAFE_TRIP == "%M612"
        assert COIL_CIP_PROFISAFE_GATEWAY_HEALTHY == "%M611"
        assert COIL_CIP_PROFISAFE_GATEWAY_TRIP == "%M612"
        assert COIL_GATEWAY_HEALTHY == "%M611"
        assert COIL_GATEWAY_TRIP == "%M612"
        assert COIL_CIP_SAFETY_PROFISAFE_HEALTHY == "%M611"
        assert COIL_CIP_SAFETY_PROFISAFE_TRIP == "%M612"

    def test_diagnostic_codes_values_and_names(self) -> None:
        assert int(DIAG_OK) == 0x0000
        assert int(DIAG_ERR_CIP_SAFETY_CRC) == 0xEE41
        assert int(DIAG_ERR_PROFISAFE_CRC) == 0xEE42
        assert int(DIAG_ERR_GATEWAY_LATENCY_EXCEEDED) == 0xEE43
        assert int(DIAG_ERR_WATCHDOG_TIMEOUT) == 0xEE44
        assert int(DIAG_ERR_F_STATUS_FAULT) == 0xEE45
        assert int(DIAG_ERR_SNN_MISMATCH) == 0xEE46

        # Compatibility aliases
        assert int(DIAG_ERR_LATENCY_EXCEEDED) == 0xEE43
        assert int(DIAG_ERR_TIMEOUT) == 0xEE44
        assert int(DIAG_ERR_SEQUENCE_MISMATCH) == 0xEE44
        assert int(DIAG_ERR_TRANSLATION_FAULT) == 0xEE46

        assert DIAG_CIP_SAFETY_CRC == DIAG_ERR_CIP_SAFETY_CRC
        assert DIAG_CIP_CRC_FAULT == DIAG_ERR_CIP_SAFETY_CRC
        assert DIAG_CIP_CRC_ERROR == DIAG_ERR_CIP_SAFETY_CRC
        assert DIAG_ERR_CRC_S1_S2 == DIAG_ERR_CIP_SAFETY_CRC

        assert DIAG_PROFISAFE_CRC == DIAG_ERR_PROFISAFE_CRC
        assert DIAG_PROFISAFE_CRC_FAULT == DIAG_ERR_PROFISAFE_CRC
        assert DIAG_PROFISAFE_CRC_ERROR == DIAG_ERR_PROFISAFE_CRC
        assert DIAG_ERR_F_CRC == DIAG_ERR_PROFISAFE_CRC

        assert DIAG_LATENCY_EXCEEDED == DIAG_ERR_GATEWAY_LATENCY_EXCEEDED
        assert DIAG_FORWARDING_LATENCY == DIAG_ERR_GATEWAY_LATENCY_EXCEEDED
        assert DIAG_WATCHDOG_TIMEOUT == DIAG_ERR_WATCHDOG_TIMEOUT
        assert DIAG_PACKET_TIMEOUT == DIAG_ERR_WATCHDOG_TIMEOUT

    def test_diagnostic_code_signed_unsigned_equality(self) -> None:
        code = DiagnosticCode(0xEE41, "CIP_SAFETY_CRC")
        # 0xEE41 as unsigned = 60993, as signed 16-bit = -4543
        assert code == 0xEE41
        assert code == 60993
        assert code == -4543
        assert (code & 0xFFFF) == 0xEE41
        assert (0xEE41 & code) == 0xEE41
        assert str(code) == "0xEE41"
        assert repr(code) == "DiagnosticCode(0xEE41)"

        # Test remaining diagnostic codes
        assert DiagnosticCode(0xEE42) == 0xEE42
        assert DiagnosticCode(0xEE43) == 0xEE43
        assert DiagnosticCode(0xEE44) == 0xEE44
        assert DiagnosticCode(0xEE45) == 0xEE45
        assert DiagnosticCode(0xEE46) == 0xEE46

    def test_gateway_state_enums_and_aliases(self) -> None:
        assert GatewayState.GATEWAY_INIT == 0
        assert GatewayState.GATEWAY_CONNECTING == 1
        assert GatewayState.GATEWAY_RUNNING == 2
        assert GatewayState.GATEWAY_SAFETY_TRIP == 3

        assert GatewayState.INIT == 0
        assert GatewayState.CONNECTING == 1
        assert GatewayState.RUNNING == 2
        assert GatewayState.SAFETY_TRIP == 3
        assert GatewayState.FAULT == 3
        assert GatewayState.TRIPPED == 3

        assert CipSafetyProfisafeState == GatewayState
        assert ProfisafeGatewayState == GatewayState
        assert BridgeState == GatewayState
        assert SafetyGatewayState == GatewayState
        assert GatewayBridgeState == GatewayState

    def test_bridge_mode_enums(self) -> None:
        assert BridgeMode.DISABLED == 0
        assert BridgeMode.CIP_TO_PROFISAFE == 1
        assert BridgeMode.PROFISAFE_TO_CIP == 2
        assert BridgeMode.BIDIRECTIONAL == 3
        assert BridgeMode.BIDIRECTIONAL_BRIDGE == 3
        assert BridgeMode.BIDIRECTIONAL_SAFE_BRIDGE == 3
        assert CipSafetyProfisafeMode == BridgeMode

    def test_status_bits_flags_and_masks(self) -> None:
        assert CipSafetyProfisafeStatusBits.BRIDGE_ONLINE == 0x0001
        assert CipSafetyProfisafeStatusBits.RUNNING == 0x0002
        assert CipSafetyProfisafeStatusBits.CONNECTING == 0x0004
        assert CipSafetyProfisafeStatusBits.CIP_SAFETY_CRC_FAULT == 0x0008
        assert CipSafetyProfisafeStatusBits.PROFISAFE_CRC_FAULT == 0x0010
        assert CipSafetyProfisafeStatusBits.LATENCY_EXCEEDED == 0x0020
        assert CipSafetyProfisafeStatusBits.WATCHDOG_TIMEOUT == 0x0040
        assert CipSafetyProfisafeStatusBits.F_STATUS_FAULT == 0x0080
        assert CipSafetyProfisafeStatusBits.SNN_MISMATCH == 0x0100
        assert CipSafetyProfisafeStatusBits.CIP_ACTIVE == 0x0200
        assert CipSafetyProfisafeStatusBits.PROFISAFE_ACTIVE == 0x0400
        assert CipSafetyProfisafeStatusBits.BIDIRECTIONAL_ACTIVE == 0x0800
        assert CipSafetyProfisafeStatusBits.SAFETY_TRIP == 0x1000

        assert ProfisafeGatewayStatusBits == CipSafetyProfisafeStatusBits
        assert GatewayStatusBits == CipSafetyProfisafeStatusBits

    def test_exception_hierarchy(self) -> None:
        assert issubclass(CipSafetyCrcError, CipSafetyProfisafeError)
        assert issubclass(ProfisafeCrcError, CipSafetyProfisafeError)
        assert issubclass(GatewayLatencyExceededError, CipSafetyProfisafeError)
        assert issubclass(GatewayWatchdogTimeoutError, CipSafetyProfisafeError)
        assert issubclass(ProfisafeFStatusFaultError, CipSafetyProfisafeError)
        assert issubclass(CipSafetySnnMismatchError, CipSafetyProfisafeError)
        assert issubclass(GatewayTimeoutError, CipSafetyProfisafeError)
        assert issubclass(GatewaySequenceError, CipSafetyProfisafeError)
        assert issubclass(GatewayLatencyError, CipSafetyProfisafeError)
        assert issubclass(GatewayTranslationError, CipSafetyProfisafeError)
        assert issubclass(CipSafetyProfisafeError, Exception)


# ============================================================================
# 2. TestCrcAlgorithms
# ============================================================================

class TestCrcAlgorithms:
    """Validate CIP Safety dual CRC (CRC-S1/S2) and PROFIsafe F-CRC algorithms."""

    def test_crc_polynomial_constants(self) -> None:
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CRC_INIT == 0xFFFF
        assert PROFISAFE_F_CRC_32_POLY == 0x1EDC6F41
        assert PROFISAFE_F_CRC_24_POLY == 0x5D45
        assert PROFISAFE_F_CRC_16_POLY == 0x1021
        assert PROFISAFE_F_CRC_INIT == 0x00000000
        assert F_CRC_32_POLY == 0x1EDC6F41
        assert F_CRC_24_POLY == 0x5D45
        assert F_CRC_16_POLY == 0x1021

    def test_cip_safety_crc_s1_bounds_and_determinism(self) -> None:
        payload = b"\x01\x02\x03\x04\x05\x06"
        c1 = calculate_cip_safety_crc_s1(payload)
        c2 = calculate_cip_safety_crc_s1(payload)
        assert c1 == c2
        assert 0 <= c1 <= 0xFFFF
        assert calculate_crc_s1(payload) == c1
        assert compute_crc_s1(payload) == c1

    def test_cip_safety_crc_s2_inverted_header(self) -> None:
        seq = 1
        ts = 1000
        snn = 0x1A2B
        raw = seq.to_bytes(2, "big") + ts.to_bytes(4, "big") + snn.to_bytes(2, "big")
        inverted = bytes(~b & 0xFF for b in raw)

        c1 = calculate_cip_safety_crc_s2(inverted)
        c2 = calculate_cip_safety_crc_s2(inverted)
        assert c1 == c2
        assert 0 <= c1 <= 0xFFFF
        assert calculate_crc_s2(inverted) == c1
        assert compute_crc_s2(inverted) == c1

    def test_profisafe_fcrc_32bit_determinism_and_bounds(self) -> None:
        data = b"\x10\x20\x30\x40"
        f1 = calculate_profisafe_f_crc32(data)
        f2 = calculate_profisafe_f_crc32(data)
        assert f1 == f2
        assert 0 <= f1 <= 0xFFFFFFFF
        assert calculate_profisafe_f_crc(data, crc_bit_length=32) == f1
        assert calculate_fcrc(data) == f1
        assert compute_fcrc(data) == f1

    def test_profisafe_fcrc_24bit_determinism_and_bounds(self) -> None:
        data = b"\xAA\xBB\xCC"
        f1 = calculate_profisafe_f_crc24(data)
        f2 = calculate_profisafe_f_crc24(data)
        assert f1 == f2
        assert 0 <= f1 <= 0xFFFFFF
        assert calculate_profisafe_f_crc(data, crc_bit_length=24) == f1

    def test_crc_single_bit_flip_sensitivity(self) -> None:
        orig = b"\xDE\xAD\xBE\xEF"
        c_orig = calculate_cip_safety_crc_s1(orig)
        f32_orig = calculate_profisafe_f_crc32(orig)
        f24_orig = calculate_profisafe_f_crc24(orig)

        for bit in range(8):
            mutated = bytearray(orig)
            mutated[1] ^= (1 << bit)
            mutated_bytes = bytes(mutated)
            assert calculate_cip_safety_crc_s1(mutated_bytes) != c_orig
            assert calculate_profisafe_f_crc32(mutated_bytes) != f32_orig
            assert calculate_profisafe_f_crc24(mutated_bytes) != f24_orig

    def test_crc_function_aliases(self) -> None:
        data = b"\x01\x02\x03\x04"
        assert calculate_profisafe_fcrc(data) == calculate_profisafe_f_crc(data)
        assert compute_profisafe_fcrc(data) == calculate_profisafe_f_crc(data)
        assert calculate_profisafe_crc(data) == calculate_profisafe_f_crc(data)
        assert compute_profisafe_crc(data) == calculate_profisafe_f_crc(data)
        assert calculate_profisafe_fcrc16(data) == calculate_profisafe_f_crc(data)


# ============================================================================
# 3. TestFrameModels
# ============================================================================

class TestFrameModels:
    """Validate CipSafetyFrame and ProfisafeFrame dataclasses and serialization."""

    def test_cip_safety_frame_defaults_and_validation(self) -> None:
        frame = CipSafetyFrame(payload=b"\x01\x02\x03\x04")
        frame.compute_crcs()
        assert frame.sequence_number == 0
        assert frame.safety_network_number == DEFAULT_SAFETY_NETWORK_NUMBER
        assert frame.crc_s1 != 0
        assert frame.crc_s2 != 0
        assert frame.validate_crcs() is True

    def test_cip_safety_frame_payload_mutation(self) -> None:
        frame = CipSafetyFrame(payload=b"\x01\x02\x03\x04")
        frame.compute_crcs()
        assert frame.validate_crcs() is True
        frame.mutate_payload(byte_offset=0, bit_pos=0)
        assert frame.validate_crcs() is False

    def test_cip_safety_frame_crc_mutations(self) -> None:
        frame1 = CipSafetyFrame(payload=b"\x01\x02\x03\x04")
        frame1.compute_crcs()
        frame1.mutate_crc_s1()
        assert frame1.validate_crcs() is False

        frame2 = CipSafetyFrame(payload=b"\x01\x02\x03\x04")
        frame2.compute_crcs()
        frame2.mutate_crc_s2()
        assert frame2.validate_crcs() is False

    def test_cip_safety_frame_serialization_roundtrip(self) -> None:
        frame = CipSafetyFrame(
            payload=b"\x12\x34\x56\x78\x9A",
            sequence_number=123,
            timestamp_us=456789,
            safety_network_number=0x1A2B,
        )
        frame.compute_crcs()
        data = frame.to_bytes()
        reconstructed = CipSafetyFrame.from_bytes(data)
        assert reconstructed.payload == frame.payload
        assert reconstructed.sequence_number == frame.sequence_number
        assert reconstructed.timestamp_us == frame.timestamp_us
        assert reconstructed.safety_network_number == frame.safety_network_number
        assert reconstructed.crc_s1 == frame.crc_s1
        assert reconstructed.crc_s2 == frame.crc_s2
        assert reconstructed.validate_crcs() is True

    def test_profisafe_frame_defaults_and_validation(self) -> None:
        frame = ProfisafeFrame(payload=b"\xAA\xBB\xCC")
        frame.compute_crc()
        assert frame.f_status == 0x00
        assert frame.f_dest_add == DEFAULT_F_DEST_ADD
        assert frame.f_crc != 0
        assert frame.validate_crc() is True

    def test_profisafe_frame_mutation_detection(self) -> None:
        frame = ProfisafeFrame(payload=b"\xAA\xBB\xCC")
        frame.compute_crc()
        assert frame.validate_crc() is True
        frame.mutate_crc()
        assert frame.validate_crc() is False

        frame2 = ProfisafeFrame(payload=b"\xAA\xBB\xCC")
        frame2.compute_crc()
        frame2.mutate_payload()
        assert frame2.validate_crc() is False

    def test_profisafe_frame_fail_safe_active(self) -> None:
        frame = ProfisafeFrame(payload=b"\x00\x00", fail_safe_active=True, f_status=0x20)
        assert frame.is_fail_safe_active() is True

        frame_normal = ProfisafeFrame(payload=b"\x01\x02", fail_safe_active=False, f_status=0x00)
        assert frame_normal.is_fail_safe_active() is False

    def test_profisafe_frame_serialization_roundtrip_32bit(self) -> None:
        frame = ProfisafeFrame(
            payload=b"\x55\x66\x77\x88",
            f_status=0x00,
            f_counter=42,
            f_source_add=1,
            f_dest_add=2,
            crc_bit_length=32,
        )
        frame.compute_crc()
        data = frame.to_bytes()
        reconstructed = ProfisafeFrame.from_bytes(data)
        assert reconstructed.payload == frame.payload
        assert reconstructed.f_status == frame.f_status
        assert reconstructed.f_counter == frame.f_counter
        assert reconstructed.f_crc == frame.f_crc
        assert reconstructed.validate_crc() is True

    def test_profisafe_frame_serialization_roundtrip_24bit(self) -> None:
        frame = ProfisafeFrame(
            payload=b"\x11\x22\x33",
            f_status=0x00,
            f_counter=10,
            f_source_add=1,
            f_dest_add=2,
            crc_bit_length=24,
        )
        frame.compute_crc()
        data = frame.to_bytes()
        reconstructed = ProfisafeFrame.from_bytes(data)
        assert reconstructed.payload == frame.payload
        assert reconstructed.crc_bit_length == 24
        assert reconstructed.validate_crc() is True

    def test_truncated_buffer_error_handling(self) -> None:
        with pytest.raises(ValueError):
            CipSafetyFrame.from_bytes(b"\x00" * 8)
        with pytest.raises(ValueError):
            ProfisafeFrame.from_bytes(b"\x00" * 6)


# ============================================================================
# 4. TestGatewayStateTransitions
# ============================================================================

class TestGatewayStateTransitions:
    """Validate gateway lifecycle, state machine transitions, and watchdogs."""

    def test_unconfigured_initial_state(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine(auto_activate=False)
        assert gw.state == GatewayState.GATEWAY_INIT
        assert gw.is_healthy is False
        assert gw.is_tripped is False
        assert gw.diagnostic_code == DIAG_OK

    def test_auto_activated_initial_state(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine(auto_activate=True)
        assert gw.state == GatewayState.GATEWAY_RUNNING
        assert gw.is_healthy is True
        assert gw.is_tripped is False
        assert gw.diagnostic_code == DIAG_OK

    def test_connect_and_forwarding_transitions(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine(auto_activate=False)
        gw.connect()
        assert gw.state == GatewayState.GATEWAY_CONNECTING

        gw.complete_connection()
        assert gw.state == GatewayState.GATEWAY_RUNNING
        assert gw.is_healthy is True

    def test_disconnect_transition(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine(auto_activate=True)
        gw.disconnect()
        assert gw.state == GatewayState.GATEWAY_INIT
        assert gw.is_healthy is False

    def test_fail_safe_trip_and_clear_faults(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine(auto_activate=True)
        gw.trip_fail_safe(DIAG_ERR_WATCHDOG_TIMEOUT)
        assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
        assert gw.is_tripped is True
        assert gw.is_healthy is False
        assert gw.diagnostic_code == DIAG_ERR_WATCHDOG_TIMEOUT
        assert gw.error_count == 1

        gw.clear_faults()
        assert gw.state == GatewayState.GATEWAY_RUNNING
        assert gw.is_healthy is True
        assert gw.is_tripped is False
        assert gw.diagnostic_code == DIAG_OK

    def test_watchdog_heartbeat_timeout(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine(watchdog_timeout_ms=100.0)
        assert gw.is_healthy is True

        # Scan step under timeout threshold
        gw.scan_step(dt=0.050)
        assert gw.is_healthy is True

        # Scan step exceeding timeout threshold (dt=0.060 -> cumulative 110ms > 100ms)
        gw.scan_step(dt=0.060)
        assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
        assert gw.diagnostic_code == DIAG_ERR_WATCHDOG_TIMEOUT
        assert gw.is_tripped is True

    def test_feed_heartbeat_prevents_timeout(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine(watchdog_timeout_ms=100.0)
        for _ in range(5):
            gw.scan_step(dt=0.050)
            gw.feed_heartbeat()
            assert gw.is_healthy is True


# ============================================================================
# 5. TestBidirectionalTranslationMapping
# ============================================================================

class TestBidirectionalTranslationMapping:
    """Validate bidirectional translation between CIP Safety and PROFIsafe."""

    def test_cip_to_profisafe_bit_exact_payload(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        payload = b"\x01\x02\x03\x04\x05"
        cip_in = gw.create_cip_safety_frame(payload=payload)
        profi_out = gw.translate_cip_to_profisafe(cip_in)

        assert profi_out is not None
        assert profi_out.payload == payload
        assert profi_out.validate_crc() is True
        assert profi_out.f_status == 0x00

    def test_profisafe_to_cip_bit_exact_payload(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        payload = b"\x10\x20\x30\x40"
        profi_in = gw.create_profisafe_frame(payload=payload)
        cip_out = gw.translate_profisafe_to_cip(profi_in)

        assert cip_out is not None
        assert cip_out.payload == payload
        assert cip_out.validate_crcs() is True

    def test_counter_tracking(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        for i in range(1, 6):
            cf = gw.create_cip_safety_frame(payload=b"\x01")
            pf = gw.translate_cip_to_profisafe(cf)
            assert pf is not None
            assert gw.cip_sequence == cf.sequence_number
            assert pf.f_counter == gw.profisafe_counter

    def test_variable_payload_sizes(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        test_payloads = [
            b"\x01",
            b"\x01\x02",
            b"\x01\x02\x03\x04",
            b"\x01\x02\x03\x04\x05\x06\x07\x08",
            bytes(range(16)),
            bytes(range(32)),
        ]
        for p in test_payloads:
            cf = gw.create_cip_safety_frame(payload=p)
            pf = gw.translate_cip_to_profisafe(cf)
            assert pf is not None
            assert pf.payload == p
            assert pf.validate_crc() is True

            cf_back = gw.translate_profisafe_to_cip(pf)
            assert cf_back is not None
            assert cf_back.payload == p
            assert cf_back.validate_crcs() is True

    def test_create_and_receive_frame_helpers(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        cf = gw.create_cip_safety_frame(b"\xAA\xBB")
        pf = gw.receive_cip_safety_frame(cf)
        assert pf is not None
        assert pf.payload == b"\xAA\xBB"

        pf2 = gw.create_profisafe_frame(b"\xCC\xDD")
        cf2 = gw.receive_profisafe_frame(pf2)
        assert cf2 is not None
        assert cf2.payload == b"\xCC\xDD"

    def test_corrupted_cip_frame_translation_fails(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        cf = gw.create_cip_safety_frame(payload=b"\x01\x02\x03\x04")
        cf.mutate_crc_s1()
        res = gw.translate_cip_to_profisafe(cf)

        assert res is None
        assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
        assert gw.diagnostic_code == DIAG_ERR_CIP_SAFETY_CRC

    def test_corrupted_profisafe_frame_translation_fails(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        pf = gw.create_profisafe_frame(payload=b"\x01\x02\x03\x04")
        pf.mutate_crc()
        res = gw.translate_profisafe_to_cip(pf)

        assert res is None
        assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
        assert gw.diagnostic_code == DIAG_ERR_PROFISAFE_CRC

    def test_tripped_gateway_emits_failsafe_substitute_frames(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        gw.trip_fail_safe(DIAG_ERR_CIP_SAFETY_CRC)

        cf = gw.create_cip_safety_frame(payload=b"\x12\x34")
        pf_sub = gw.translate_cip_to_profisafe(cf)
        assert pf_sub is not None
        assert pf_sub.fail_safe_active is True
        assert pf_sub.payload == b"\x00\x00"

        pf = gw.create_profisafe_frame(payload=b"\x56\x78")
        cf_sub = gw.translate_profisafe_to_cip(pf)
        assert cf_sub is not None
        assert cf_sub.payload == b"\x00\x00"


# ============================================================================
# 6. TestLatencyMeasurementAndThresholds
# ============================================================================

class TestLatencyMeasurementAndThresholds:
    """Validate gateway forwarding latency measurement and threshold surveillance."""

    def test_nominal_forwarding_latency_tracking(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        cf = gw.create_cip_safety_frame(payload=b"\x01\x02")
        gw.translate_cip_to_profisafe(cf)
        assert gw.translation_latency_us == DEFAULT_TRANSLATION_LATENCY_US
        assert gw.is_healthy is True

    def test_simulated_latency_tracking(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        cf = gw.create_cip_safety_frame(payload=b"\x01\x02")
        gw.translate_cip_to_profisafe(cf, simulated_latency_us=1200)
        assert gw.translation_latency_us == 1200
        assert gw.is_healthy is True

    def test_latency_exceeding_threshold_trips_0xEE43(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        cf = gw.create_cip_safety_frame(payload=b"\x01\x02")
        res = gw.translate_cip_to_profisafe(cf, simulated_latency_us=5500)

        assert res is None
        assert gw.translation_latency_us == 5500
        assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
        assert gw.diagnostic_code == DIAG_ERR_GATEWAY_LATENCY_EXCEEDED
        assert gw.is_tripped is True
        assert (gw.status_word & int(CipSafetyProfisafeStatusBits.LATENCY_EXCEEDED)) != 0

    def test_reverse_translation_latency_exceeded(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        pf = gw.create_profisafe_frame(payload=b"\x01\x02")
        res = gw.translate_profisafe_to_cip(pf, simulated_latency_us=6000)

        assert res is None
        assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
        assert gw.diagnostic_code == DIAG_ERR_GATEWAY_LATENCY_EXCEEDED
        assert gw.is_tripped is True

    def test_clear_faults_restores_nominal_latency(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        gw.inject_latency_exceeded(7000)
        assert gw.is_tripped is True
        gw.clear_faults()
        assert gw.is_healthy is True
        assert gw.translation_latency_us == DEFAULT_TRANSLATION_LATENCY_US

    def test_inject_latency_exceeded_helper(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        gw.inject_latency_exceeded(5200)
        assert gw.translation_latency_us == 5200
        assert gw.diagnostic_code == DIAG_ERR_GATEWAY_LATENCY_EXCEEDED


# ============================================================================
# 7. TestDiagnosticCodesAndFailSafeTrips
# ============================================================================

class TestDiagnosticCodesAndFailSafeTrips:
    """Validate all diagnostic codes (0xEE41..0xEE46), fail-safe trips, and timings."""

    def test_trip_cip_safety_crc_0xEE41(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        gw.inject_cip_crc_error()
        assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
        assert gw.diagnostic_code == DIAG_ERR_CIP_SAFETY_CRC
        assert gw.diagnostic_code == 0xEE41
        assert (gw.status_word & int(CipSafetyProfisafeStatusBits.CIP_SAFETY_CRC_FAULT)) != 0
        assert (gw.status_word & int(CipSafetyProfisafeStatusBits.SAFETY_TRIP)) != 0

    def test_trip_profisafe_crc_0xEE42(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        gw.inject_profisafe_crc_error()
        assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
        assert gw.diagnostic_code == DIAG_ERR_PROFISAFE_CRC
        assert gw.diagnostic_code == 0xEE42
        assert (gw.status_word & int(CipSafetyProfisafeStatusBits.PROFISAFE_CRC_FAULT)) != 0

    def test_trip_latency_exceeded_0xEE43(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        gw.inject_latency_exceeded()
        assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
        assert gw.diagnostic_code == DIAG_ERR_GATEWAY_LATENCY_EXCEEDED
        assert gw.diagnostic_code == 0xEE43
        assert (gw.status_word & int(CipSafetyProfisafeStatusBits.LATENCY_EXCEEDED)) != 0

    def test_trip_watchdog_timeout_0xEE44(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        gw.inject_watchdog_timeout()
        assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
        assert gw.diagnostic_code == DIAG_ERR_WATCHDOG_TIMEOUT
        assert gw.diagnostic_code == 0xEE44
        assert (gw.status_word & int(CipSafetyProfisafeStatusBits.WATCHDOG_TIMEOUT)) != 0

    def test_trip_f_status_fault_0xEE45(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        gw.inject_f_status_fault()
        assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
        assert gw.diagnostic_code == DIAG_ERR_F_STATUS_FAULT
        assert gw.diagnostic_code == 0xEE45
        assert (gw.status_word & int(CipSafetyProfisafeStatusBits.F_STATUS_FAULT)) != 0

    def test_trip_snn_mismatch_0xEE46(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        gw.inject_snn_mismatch()
        assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
        assert gw.diagnostic_code == DIAG_ERR_SNN_MISMATCH
        assert gw.diagnostic_code == 0xEE46
        assert (gw.status_word & int(CipSafetyProfisafeStatusBits.SNN_MISMATCH)) != 0

    def test_fail_safe_trip_increments_error_count(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        assert gw.error_count == 0
        gw.trip_fail_safe(DIAG_ERR_WATCHDOG_TIMEOUT)
        assert gw.error_count == 1
        gw.trip_fail_safe(DIAG_ERR_CIP_SAFETY_CRC)
        assert gw.error_count == 2

    def test_snn_mismatch_during_translation(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine(expected_snn=0x1A2B)
        cf = CipSafetyFrame(payload=b"\x01\x02", safety_network_number=0x9999)
        cf.compute_crcs()
        res = gw.translate_cip_to_profisafe(cf)
        assert res is None
        assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
        assert gw.diagnostic_code == DIAG_ERR_SNN_MISMATCH


# ============================================================================
# 8. TestHornerRegisterTableSync
# ============================================================================

class TestHornerRegisterTableSync:
    """Validate bit-exact Horner RegisterTable synchronization and signed 16-bit masking."""

    def test_nominal_register_synchronization(self) -> None:
        rt = RegisterTable()
        gw = CipSafetyProfisafeBridgeEngine(register_table=rt)
        gw.sync_to_registers(rt)

        w_status = rt.read_word(REG_CIP_PROFISAFE_STATUS) & 0xFFFF
        w_seq = rt.read_word(REG_CIP_PROFISAFE_CIP_SEQUENCE) & 0xFFFF
        w_counter = rt.read_word(REG_CIP_PROFISAFE_PROFISAFE_COUNTER) & 0xFFFF
        w_latency = rt.read_word(REG_CIP_PROFISAFE_TRANSLATION_LATENCY_US) & 0xFFFF
        w_word = rt.read_word(REG_CIP_PROFISAFE_STATUS_WORD) & 0xFFFF
        w_diag = rt.read_word(REG_CIP_PROFISAFE_DIAGNOSTIC_CODE) & 0xFFFF
        w_err = rt.read_word(REG_CIP_PROFISAFE_ERROR_COUNT) & 0xFFFF
        w_fps = rt.read_word(REG_CIP_PROFISAFE_THROUGHPUT_FPS) & 0xFFFF

        assert w_status == gw.status_register_value
        assert w_seq == 0
        assert w_counter == 0
        assert w_latency == DEFAULT_TRANSLATION_LATENCY_US
        assert (w_word & 1) == 1  # BRIDGE_ONLINE
        assert w_diag == 0x0000
        assert w_err == 0
        assert w_fps == DEFAULT_THROUGHPUT_FPS

        assert rt.read_bit(COIL_CIP_PROFISAFE_BRIDGE_ONLINE) is True
        assert rt.read_bit(COIL_CIP_PROFISAFE_SAFETY_TRIP) is False

    def test_tripped_register_sync_and_signed_16bit_masking(self) -> None:
        rt = RegisterTable()
        gw = CipSafetyProfisafeBridgeEngine(register_table=rt)

        # Test each diagnostic code with signed 16-bit masking
        diag_codes = [
            (DIAG_ERR_CIP_SAFETY_CRC, 0xEE41),
            (DIAG_ERR_PROFISAFE_CRC, 0xEE42),
            (DIAG_ERR_GATEWAY_LATENCY_EXCEEDED, 0xEE43),
            (DIAG_ERR_WATCHDOG_TIMEOUT, 0xEE44),
            (DIAG_ERR_F_STATUS_FAULT, 0xEE45),
            (DIAG_ERR_SNN_MISMATCH, 0xEE46),
        ]

        for code, expected_hex in diag_codes:
            gw.trip_fail_safe(code)
            gw.sync_to_registers(rt)

            raw_word = rt.read_word(REG_CIP_PROFISAFE_DIAGNOSTIC_CODE)
            # Crucial requirement: signed 16-bit masking
            assert (raw_word & 0xFFFF) == expected_hex
            assert rt.read_bit(COIL_CIP_PROFISAFE_BRIDGE_ONLINE) is False
            assert rt.read_bit(COIL_CIP_PROFISAFE_SAFETY_TRIP) is True
            gw.clear_faults()

    def test_sync_with_different_privilege_modes(self) -> None:
        rt = RegisterTable()
        gw = CipSafetyProfisafeBridgeEngine(register_table=rt)
        gw.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert (rt.read_word(REG_CIP_PROFISAFE_STATUS) & 0xFFFF) != 0

        gw.sync_to_registers(rt, privilege=PrivilegeMode.APPLICATION)
        assert (rt.read_word(REG_CIP_PROFISAFE_STATUS) & 0xFFFF) != 0

    def test_sync_to_external_register_table(self) -> None:
        rt_ext = RegisterTable()
        gw = CipSafetyProfisafeBridgeEngine()
        gw.sync_to_registers(rt_ext)
        assert (rt_ext.read_word(REG_CIP_PROFISAFE_TRANSLATION_LATENCY_US) & 0xFFFF) == DEFAULT_TRANSLATION_LATENCY_US
        assert rt_ext.read_bit(COIL_CIP_PROFISAFE_BRIDGE_ONLINE) is True


# ============================================================================
# 9. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface compliance (scan_step, step, execute, reset)."""

    def test_logic_unit_properties(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        assert gw.name == "CipSafetyProfisafeBridgeEngine"
        assert gw.priority == 10
        assert gw.is_enabled is True
        assert isinstance(gw, ILogicUnit)

    def test_scan_step_with_context(self) -> None:
        rt = RegisterTable()
        ctx = ScanContext(register_table=rt, dt=0.010)
        gw = CipSafetyProfisafeBridgeEngine()
        result = gw.scan_step(ctx)

        assert isinstance(result, ExecutionResult)
        assert result.status == AgentStatus.SUCCESS
        assert result.error_code is None
        assert (rt.read_word(REG_CIP_PROFISAFE_STATUS_WORD) & 1) == 1

    def test_scan_step_with_dt_and_context(self) -> None:
        rt = RegisterTable()
        ctx = ScanContext(register_table=rt, dt=0.020)
        gw = CipSafetyProfisafeBridgeEngine()
        result = gw.scan_step(0.020, ctx)
        assert result.status == AgentStatus.SUCCESS
        assert gw.cycles_count == 1

    def test_scan_step_kwargs(self) -> None:
        rt = RegisterTable()
        gw = CipSafetyProfisafeBridgeEngine()
        result = gw.scan_step(dt_ms=10.0, register_table=rt)
        assert result.status == AgentStatus.SUCCESS
        assert gw.cycles_count == 1

    def test_step_and_execute_methods(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        gw.step(dt=0.010)
        assert gw.cycles_count == 1
        res = gw.execute()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert gw.cycles_count == 2

    def test_reset_method(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        cf = gw.create_cip_safety_frame(b"\x01")
        gw.translate_cip_to_profisafe(cf)
        gw.trip_fail_safe(DIAG_ERR_WATCHDOG_TIMEOUT)
        assert gw.is_tripped is True
        assert gw.error_count == 1

        gw.reset()
        assert gw.cycles_count == 0
        assert gw.error_count == 0
        assert gw.cip_sequence == 0
        assert gw.profisafe_counter == 0
        assert gw.is_healthy is True

    def test_scan_step_failure_status_when_tripped(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        gw.trip_fail_safe(DIAG_ERR_CIP_SAFETY_CRC)
        res = gw.scan_step()
        assert res.status == AgentStatus.FAILED
        assert res.error_code == str(DIAG_ERR_CIP_SAFETY_CRC)


# ============================================================================
# 10. TestPureIEC61131StructuredTextAndSecurity
# ============================================================================

class TestPureIEC61131StructuredTextAndSecurity:
    """Validate pure IEC 61131-3 Structured Text POU and anti-ladder security enforcement."""

    def test_pure_st_pou_syntax_and_register_bindings(self) -> None:
        assert verify_cip_safety_profisafe_pure_st() is True

        # Parse AST directly
        ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_PROFISAFE_BRIDGE_SYNC)
        assert ast.name == "CipSafetyProfisafeBridgeSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_registers = {
            "%R2620", "%R2621", "%R2622", "%R2623",
            "%R2624", "%R2625", "%R2626", "%R2627",
            "%M611", "%M612",
        }
        for reg in expected_registers:
            assert reg in ast.bound_registers

    def test_security_guard_assert_pure_st_content(self) -> None:
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_PROFISAFE_BRIDGE_SYNC)

    def test_ladder_contacts_rejection(self) -> None:
        contacts = [
            "PROGRAM Test ---[ ]--- x; END_PROGRAM",
            "PROGRAM Test ---[/]--- x; END_PROGRAM",
            "PROGRAM Test --[ ]-- x; END_PROGRAM",
            "PROGRAM Test --[/]-- x; END_PROGRAM",
        ]
        for c in contacts:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(c)

    def test_ladder_coils_rejection(self) -> None:
        coils = [
            "PROGRAM Test ---( )--- y; END_PROGRAM",
            "PROGRAM Test ---(S)--- y; END_PROGRAM",
            "PROGRAM Test ---(R)--- y; END_PROGRAM",
            "PROGRAM Test --( )-- y; END_PROGRAM",
        ]
        for c in coils:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(c)

    def test_ladder_rungs_and_networks_rejection(self) -> None:
        delimiters = [
            "PROGRAM Test RUNG 1 END_PROGRAM",
            "PROGRAM Test END_RUNG END_PROGRAM",
            "PROGRAM Test NETWORK 1 END_PROGRAM",
            "PROGRAM Test END_NETWORK END_PROGRAM",
        ]
        for d in delimiters:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(d)

    def test_ladder_mnemonics_rejection(self) -> None:
        mnemonics = [
            "PROGRAM Test XIC(Contact1); END_PROGRAM",
            "PROGRAM Test XIO(Contact1); END_PROGRAM",
            "PROGRAM Test OTE(Coil1); END_PROGRAM",
            "PROGRAM Test OTL(Coil1); END_PROGRAM",
            "PROGRAM Test OTU(Coil1); END_PROGRAM",
        ]
        for m in mnemonics:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(m)


# ============================================================================
# 11. TestMultiCycleSoakAndStability
# ============================================================================

class TestMultiCycleSoakAndStability:
    """Validate 100-cycle soak stability, memory leak freedom, and zero degradation."""

    def test_100_cycle_soak_execution(self) -> None:
        rt = RegisterTable()
        ctx = ScanContext(register_table=rt, dt=0.010)
        gw = CipSafetyProfisafeBridgeEngine(register_table=rt)

        for cycle in range(100):
            res = gw.scan_step(ctx)
            assert res.status == AgentStatus.SUCCESS
            assert gw.is_healthy is True
            gw.feed_watchdog()

        assert gw.cycles_count == 100
        assert gw.error_count == 0

    def test_soak_memory_stability_tracemalloc(self) -> None:
        tracemalloc.start()
        gw = CipSafetyProfisafeBridgeEngine()

        # Warmup
        for _ in range(20):
            cf = gw.create_cip_safety_frame(b"\x01\x02\x03\x04")
            pf = gw.translate_cip_to_profisafe(cf)
            if pf is not None:
                gw.translate_profisafe_to_cip(pf)

        snapshot1 = tracemalloc.take_snapshot()

        for _ in range(100):
            cf = gw.create_cip_safety_frame(b"\x01\x02\x03\x04")
            pf = gw.translate_cip_to_profisafe(cf)
            if pf is not None:
                gw.translate_profisafe_to_cip(pf)

        snapshot2 = tracemalloc.take_snapshot()
        tracemalloc.stop()

        top_stats = snapshot2.compare_to(snapshot1, "lineno")
        total_growth = sum(stat.size_diff for stat in top_stats)
        # Verify bounded growth (< 256 KB across 100 roundtrip frames)
        assert total_growth < 256 * 1024

    def test_intermittent_fault_injection_and_recovery_soak(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        for i in range(10):
            gw.inject_watchdog_timeout()
            assert gw.is_tripped is True
            assert gw.state == GatewayState.GATEWAY_SAFETY_TRIP
            gw.clear_faults()
            assert gw.is_healthy is True
            assert gw.state == GatewayState.GATEWAY_RUNNING
        assert gw.error_count == 10

    def test_monotonic_counter_increments_during_soak(self) -> None:
        gw = CipSafetyProfisafeBridgeEngine()
        for i in range(1, 51):
            cf = gw.create_cip_safety_frame(b"\xAA")
            pf = gw.translate_cip_to_profisafe(cf)
            assert pf is not None
            assert pf.f_counter == i


# ============================================================================
# 12. TestNineStageVerificationRunner
# ============================================================================

class TestNineStageVerificationRunner:
    """Validate run_cip_safety_profisafe_verification suite and evidence emission."""

    def test_runner_returns_strict_4state_success(self) -> None:
        result = run_cip_safety_profisafe_verification()
        assert isinstance(result, dict)
        assert result.get("status") == "success"
        assert result.get("error_code") is None

    def test_runner_all_nine_stages_passed(self) -> None:
        result = run_cip_safety_profisafe_verification()
        assert result.get("stages_passed") == 9
        assert result.get("total_stages") == 9
        stages = result.get("data", {}).get("stages", [])
        assert len(stages) == 9
        for stg in stages:
            assert stg.get("passed") is True, f"Stage {stg.get('stage')} ({stg.get('name')}) failed"

    def test_evidence_file_emission(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "evidence.json"
            result = run_cip_safety_profisafe_verification(output_path=out_path)
            assert out_path.exists()
            assert out_path.stat().st_size > 0

            with open(out_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded.get("status") == "success"
            assert loaded.get("data", {}).get("work_package") == "W301"

    def test_verification_evidence_metadata(self) -> None:
        result = run_cip_safety_profisafe_verification()
        data = result.get("data", {})
        assert data.get("work_package") == "W301"
        assert data.get("gate") == "G8"
        assert "ODVA CIP Safety Volume 5" in data.get("standards", [])
        assert "%R2620..%R2627" in data.get("registers", [])
        assert "%M611..%M612" in data.get("registers", [])
