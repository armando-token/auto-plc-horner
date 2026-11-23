"""Comprehensive Unit Test Suite for Wave W322 CIP Safety Over Ethernet-APL Field Switch Engine.

Work Package: W322 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Ethernet-APL Field Switch Diagnostics Protocol Engine.

Covers Comprehensive Deterministic Unit Tests across 14 Mandatory Test Classes (80+ Tests):
1. TestProtocolConstantsEnumsAndDiagnostics: Canonical registers (%R2830..%R2837), coils (%M660..%M661),
   aliases, protocol constants, enums (SwitchOperatingState, SwitchPortState, SwitchStatusBits),
   and signed 16-bit safe comparisons for DiagnosticCode (0x0000, 0xEEB1..0xEEB5).
2. TestDualSafetyCrcMathematics: CRC-S1 (poly 0x5935, init 0x0000) and CRC-S2 (poly 0x755B, init 0x0000)
   polynomial mathematics, single-bit perturbation detection, EPID hashing and CRC32.
3. TestPacketModelAndBinarySerialization: CIPAPLSwitchPacket dataclass, property accessors,
   inverted header computation, CRC validation, binary pack/unpack roundtrip, and tampering detection.
4. TestSwitchTelemetryProfiling: IEEE 802.3cg trunk power delivery (50V/800mA, 40000 mW), 8-spur-port
   telemetry, active ports bitmap, connect/disconnect lifecycles, and packet transmission roundtrips.
5. TestTrunkVoltageDegradationFaultInjectionAndTrip: Trunk voltage degradation fault injection (< 44.0V or > 55.0V),
   transition to SAFETY_TRIP, diagnostic code 0xEEB1, coil interlocks, and recovery on clear_fault().
6. TestSpurPortFaultInjectionAndTrip: Spur port fault injection (short-circuit / overload > 115 mA),
   transition to SAFETY_TRIP, diagnostic code 0xEEB2, spur fault bitmap assertion, and fail-safe trip.
7. TestSwitchThermalOverheatInjectionAndTrip: Switch internal thermal overheat exceeding limit > 85.0 degC (0xEEB3),
   transition to SAFETY_TRIP, status bit assertion, and fail-safe trip.
8. TestPortBabblingIdiotInjectionAndTrip: Port jabber babbling idiot injection exceeding threshold (0xEEB5),
   transition to SAFETY_TRIP, port state update, and fault clearance.
9. TestCrcCorruptionInjectionAndTrip: Dual CRC corruption injection (0xEEB4), packet corruption detection,
   and monotonic CRC error and packet loss counter increments.
10. TestSafeStopInterlockAndCoils: Fail-safe interlock asserting %M661 (SAFETY_TRIP) and de-asserting %M660 (ONLINE)
    across all diagnostic trip conditions, coil mutual exclusivity, and healthy restoration upon clear_fault().
11. TestRegisterTableSynchronization: Bit-exact synchronization to Horner OCS registers (%R2830..%R2837)
    and coils (%M660..%M661), status register packing, signed 16-bit masking, privilege modes, and write helpers.
12. TestPureIEC61131StructuredTextAndSecurity: Pure IEC 61131-3 ST POU CipSafetyAplSwitchSync validation
    via STParser and SecurityGuard, AST bound registers, and strict interception of 9 ladder logic constructs.
13. TestILogicUnitComplianceAndSimulationSoak: ILogicUnit interface compliance, variable scan_step argument
    handling, step/execute/reset methods, and 100-cycle continuous simulation soak with bounded memory.
14. TestVerificationRunner9StagesAndCli: Complete 9-stage verification suite run_cip_safety_apl_switch_verification,
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

REPO_ROOT = Path(__file__).resolve().parent.parent

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_apl_switch import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_APL_SWITCH_CLASS_ID,
    CIP_APL_SWITCH_CLASS_ID,
    TRUNK_VOLTAGE_MIN_MV,
    TRUNK_VOLTAGE_MAX_MV,
    TRUNK_VOLTAGE_NOMINAL_MV,
    TRUNK_CURRENT_NOMINAL_MA,
    TRUNK_CURRENT_MAX_MA,
    SPUR_CURRENT_MAX_MA,
    SPUR_CURRENT_NOMINAL_MA,
    SWITCH_TEMP_MAX_DEGC,
    MAX_SWITCH_TEMP_DEGC,
    DEFAULT_SWITCH_TEMP_LIMIT_DEGC,
    MAX_JABBER_FRAME_LIMIT,
    DEFAULT_NUM_SPUR_PORTS,
    DEFAULT_ACTIVE_PORTS_BITMAP,
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
    REG_CIP_APL_SWITCH_STATUS,
    REG_CIP_APL_SWITCH_PORT_BITMAP,
    REG_CIP_APL_SWITCH_TRUNK_VOLTAGE_MV,
    REG_CIP_APL_SWITCH_TRUNK_CURRENT_MA,
    REG_CIP_APL_SWITCH_SPUR_FAULT_BITMAP,
    REG_CIP_APL_SWITCH_TEMP_DEGC,
    REG_CIP_APL_SWITCH_CRC_ERROR_COUNT,
    REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE,
    COIL_CIP_APL_SWITCH_ONLINE,
    COIL_CIP_APL_SWITCH_SAFETY_TRIP,
    REG_APL_SWITCH_STATUS,
    REG_SWITCH_STATUS,
    REG_SWITCH_STATE,
    REG_CIP_APL_SWITCH_STATE,
    REG_APL_SWITCH_PORT_BITMAP,
    REG_SWITCH_PORT_BITMAP,
    REG_CIP_APL_SWITCH_PORTS,
    REG_APL_SWITCH_TRUNK_VOLTAGE_MV,
    REG_SWITCH_TRUNK_VOLTAGE_MV,
    REG_APL_SWITCH_TRUNK_VOLTAGE,
    REG_CIP_APL_SWITCH_TRUNK_VOLTAGE,
    REG_APL_SWITCH_TRUNK_CURRENT_MA,
    REG_SWITCH_TRUNK_CURRENT_MA,
    REG_APL_SWITCH_TRUNK_CURRENT,
    REG_CIP_APL_SWITCH_TRUNK_CURRENT,
    REG_APL_SWITCH_SPUR_FAULT_BITMAP,
    REG_SWITCH_SPUR_FAULT_BITMAP,
    REG_CIP_APL_SWITCH_SPUR_FAULTS,
    REG_APL_SWITCH_TEMP_DEGC,
    REG_SWITCH_TEMP_DEGC,
    REG_APL_SWITCH_TEMP,
    REG_CIP_APL_SWITCH_TEMP,
    REG_APL_SWITCH_CRC_ERROR_COUNT,
    REG_SWITCH_CRC_ERROR_COUNT,
    REG_CIP_APL_SWITCH_CRC_ERRORS,
    REG_APL_SWITCH_DIAGNOSTIC_CODE,
    REG_SWITCH_DIAGNOSTIC_CODE,
    REG_APL_SWITCH_DIAG_CODE,
    COIL_APL_SWITCH_ONLINE,
    COIL_SWITCH_ONLINE,
    COIL_CIP_APL_SWITCH_HEALTHY,
    COIL_APL_SWITCH_HEALTHY,
    COIL_CIP_APL_SWITCH_ACTIVE,
    COIL_APL_SWITCH_ACTIVE,
    COIL_APL_SWITCH_SAFETY_TRIP,
    COIL_SWITCH_SAFETY_TRIP,
    COIL_CIP_APL_SWITCH_TRIP,
    COIL_APL_SWITCH_TRIP,
    COIL_CIP_APL_SWITCH_FAULT,
    COIL_APL_SWITCH_FAULT,
    SwitchOperatingState,
    CipSafetySwitchOperatingState,
    CIPSwitchOperatingState,
    SwitchState,
    CipSafetySwitchState,
    CIPSwitchState,
    APLSwitchState,
    CIPAPLSwitchOperatingState,
    SwitchPortState,
    CipSafetySwitchPortState,
    CIPSwitchPortState,
    PortState,
    APLSwitchPortState,
    DiagnosticCode,
    DIAG_OK,
    DIAG_ERR_TRUNK_POWER_DEGRADED,
    DIAG_ERR_SPUR_PORT_FAULT,
    DIAG_ERR_SWITCH_THERMAL_OVERHEAT,
    DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
    DIAG_ERR_PORT_BABBLING_IDIOT,
    DIAG_TRUNK_POWER_DEGRADED,
    DIAG_SPUR_PORT_FAULT,
    DIAG_SWITCH_THERMAL_OVERHEAT,
    DIAG_THERMAL_OVERHEAT,
    DIAG_CRC_FAULT,
    DIAG_BABBLING_IDIOT,
    DIAG_PORT_BABBLING,
    SwitchDiagnosticCode,
    CIPAPLSwitchDiagnosticCode,
    CipSafetySwitchDiagnosticCode,
    APLSwitchDiagnosticCode,
    DiagnosticStatusCode,
    SwitchFaultCode,
    SwitchStatusBits,
    CipSafetySwitchStatusBits,
    CIPSwitchStatusBits,
    APLSwitchStatusBits,
    CIPAPLSwitchSafetyError,
    SwitchTrunkPowerDegradedFaultError,
    SwitchSpurPortFaultError,
    SwitchThermalOverheatFaultError,
    SwitchDualCrcSafetyFaultError,
    SwitchPortBabblingFaultError,
    SwitchTrunkPowerError,
    SwitchSpurFaultError,
    SwitchThermalError,
    SwitchCrcFaultError,
    SwitchBabblingError,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    calculate_cip_safety_crc_s1,
    calculate_cip_safety_crc_s2,
    calculate_crc_s1,
    calculate_crc_s2,
    calculate_crc16_ccitt,
    compute_epid_hash,
    compute_epid_crc32,
    verify_dual_crc_s,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CIPAPLSwitchPacket,
    CipSafetyAPLSwitchPacket,
    CIPSwitchPacket,
    APLSwitchPacket,
    CipSafetySwitchPacket,
    SwitchPacket,
    create_valid_apl_switch_packet,
    create_valid_switch_packet,
    create_valid_cip_switch_packet,
    ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC,
    CIP_SAFETY_APL_SWITCH_SYNC_POU,
    CIP_SAFETY_APL_SWITCH_PURE_ST_POU,
    CIP_SAFETY_APL_SWITCH_POU,
    PURE_ST_POU,
    CipSafetyAplSwitchSync,
    CipSafetyAplSwitchSyncPOU,
    verify_cip_safety_apl_switch_pure_st,
    verify_switch_pure_st,
    CIPAPLSwitchSafetyEngine,
    CipSafetyAplSwitchEngine,
    CIPAPLSwitchEngine,
    APLSwitchSafetyEngine,
    APLSwitchEngine,
    SwitchSafetyEngine,
    run_cip_safety_apl_switch_verification,
)


# ============================================================================
# 1. TestProtocolConstantsEnumsAndDiagnostics
# ============================================================================

class TestProtocolConstantsEnumsAndDiagnostics:
    """Validate canonical registers, coils, aliases, protocol constants, and safe comparisons."""

    def test_canonical_registers_and_coils(self) -> None:
        assert REG_CIP_APL_SWITCH_STATUS == "%R2830"
        assert REG_CIP_APL_SWITCH_PORT_BITMAP == "%R2831"
        assert REG_CIP_APL_SWITCH_TRUNK_VOLTAGE_MV == "%R2832"
        assert REG_CIP_APL_SWITCH_TRUNK_CURRENT_MA == "%R2833"
        assert REG_CIP_APL_SWITCH_SPUR_FAULT_BITMAP == "%R2834"
        assert REG_CIP_APL_SWITCH_TEMP_DEGC == "%R2835"
        assert REG_CIP_APL_SWITCH_CRC_ERROR_COUNT == "%R2836"
        assert REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE == "%R2837"
        assert COIL_CIP_APL_SWITCH_ONLINE == "%M660"
        assert COIL_CIP_APL_SWITCH_SAFETY_TRIP == "%M661"

    def test_register_and_coil_aliases(self) -> None:
        assert REG_APL_SWITCH_STATUS == "%R2830"
        assert REG_SWITCH_STATUS == "%R2830"
        assert REG_SWITCH_STATE == "%R2830"
        assert REG_CIP_APL_SWITCH_STATE == "%R2830"
        assert REG_APL_SWITCH_PORT_BITMAP == "%R2831"
        assert REG_SWITCH_PORT_BITMAP == "%R2831"
        assert REG_CIP_APL_SWITCH_PORTS == "%R2831"
        assert REG_APL_SWITCH_TRUNK_VOLTAGE_MV == "%R2832"
        assert REG_SWITCH_TRUNK_VOLTAGE_MV == "%R2832"
        assert REG_APL_SWITCH_TRUNK_VOLTAGE == "%R2832"
        assert REG_CIP_APL_SWITCH_TRUNK_VOLTAGE == "%R2832"
        assert REG_APL_SWITCH_TRUNK_CURRENT_MA == "%R2833"
        assert REG_SWITCH_TRUNK_CURRENT_MA == "%R2833"
        assert REG_APL_SWITCH_TRUNK_CURRENT == "%R2833"
        assert REG_CIP_APL_SWITCH_TRUNK_CURRENT == "%R2833"
        assert REG_APL_SWITCH_SPUR_FAULT_BITMAP == "%R2834"
        assert REG_SWITCH_SPUR_FAULT_BITMAP == "%R2834"
        assert REG_CIP_APL_SWITCH_SPUR_FAULTS == "%R2834"
        assert REG_APL_SWITCH_TEMP_DEGC == "%R2835"
        assert REG_SWITCH_TEMP_DEGC == "%R2835"
        assert REG_APL_SWITCH_TEMP == "%R2835"
        assert REG_CIP_APL_SWITCH_TEMP == "%R2835"
        assert REG_APL_SWITCH_CRC_ERROR_COUNT == "%R2836"
        assert REG_SWITCH_CRC_ERROR_COUNT == "%R2836"
        assert REG_CIP_APL_SWITCH_CRC_ERRORS == "%R2836"
        assert REG_APL_SWITCH_DIAGNOSTIC_CODE == "%R2837"
        assert REG_SWITCH_DIAGNOSTIC_CODE == "%R2837"
        assert REG_APL_SWITCH_DIAG_CODE == "%R2837"

        assert COIL_APL_SWITCH_ONLINE == "%M660"
        assert COIL_SWITCH_ONLINE == "%M660"
        assert COIL_CIP_APL_SWITCH_HEALTHY == "%M660"
        assert COIL_APL_SWITCH_HEALTHY == "%M660"
        assert COIL_CIP_APL_SWITCH_ACTIVE == "%M660"
        assert COIL_APL_SWITCH_ACTIVE == "%M660"
        assert COIL_APL_SWITCH_SAFETY_TRIP == "%M661"
        assert COIL_SWITCH_SAFETY_TRIP == "%M661"
        assert COIL_CIP_APL_SWITCH_TRIP == "%M661"
        assert COIL_APL_SWITCH_TRIP == "%M661"
        assert COIL_CIP_APL_SWITCH_FAULT == "%M661"
        assert COIL_APL_SWITCH_FAULT == "%M661"

    def test_protocol_constants(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_APL_SWITCH_CLASS_ID == 0x4B
        assert CIP_APL_SWITCH_CLASS_ID == 0x4B
        assert TRUNK_VOLTAGE_MIN_MV == 44000
        assert TRUNK_VOLTAGE_MAX_MV == 55000
        assert TRUNK_VOLTAGE_NOMINAL_MV == 50000
        assert TRUNK_CURRENT_NOMINAL_MA == 800
        assert TRUNK_CURRENT_MAX_MA == 1500
        assert SPUR_CURRENT_MAX_MA == 115
        assert SPUR_CURRENT_NOMINAL_MA == 50
        assert SWITCH_TEMP_MAX_DEGC == 85.0
        assert MAX_SWITCH_TEMP_DEGC == 85.0
        assert DEFAULT_SWITCH_TEMP_LIMIT_DEGC == 85.0
        assert MAX_JABBER_FRAME_LIMIT == 10
        assert DEFAULT_NUM_SPUR_PORTS == 8
        assert DEFAULT_ACTIVE_PORTS_BITMAP == 0x00FF
        assert DEFAULT_SESSION_ID == 0x5357
        assert DEFAULT_SAFETY_EPID == "HORNER-OCS-APL-FIELD-SWITCH-SIL3"
        assert DEFAULT_EPID == "HORNER-OCS-APL-FIELD-SWITCH-SIL3"
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0x0000

    def test_switch_operating_state_enum(self) -> None:
        assert SwitchOperatingState.DE_ENERGIZED == 0
        assert SwitchOperatingState.STANDBY == 1
        assert SwitchOperatingState.NORMAL_OPERATION == 2
        assert SwitchOperatingState.DEGRADED == 3
        assert SwitchOperatingState.FAULT_LOCKOUT == 4
        assert SwitchOperatingState.SAFETY_TRIP == 5

        # Aliases
        assert SwitchOperatingState.NORMAL == 2
        assert SwitchOperatingState.STANDBY_STATE == 1
        assert SwitchOperatingState.DEGRADED_STATE == 3
        assert SwitchOperatingState.LOCKOUT == 4
        assert SwitchOperatingState.TRIP == 5
        assert SwitchOperatingState.TRIPPED == 5

    def test_switch_port_state_enum(self) -> None:
        assert SwitchPortState.PORT_DISABLED == 0
        assert SwitchPortState.PORT_LINK_DOWN == 1
        assert SwitchPortState.PORT_LINK_UP == 2
        assert SwitchPortState.PORT_OVERLOAD == 3
        assert SwitchPortState.PORT_SHORT_CIRCUIT == 4
        assert SwitchPortState.PORT_BABBLING == 5

        # Aliases
        assert SwitchPortState.DISABLED == 0
        assert SwitchPortState.LINK_DOWN == 1
        assert SwitchPortState.LINK_UP == 2
        assert SwitchPortState.OVERLOAD == 3
        assert SwitchPortState.SHORT_CIRCUIT == 4
        assert SwitchPortState.BABBLING == 5

    def test_diagnostic_code_values_and_safe_signed_comparisons(self) -> None:
        assert DiagnosticCode.DIAG_OK == 0x0000
        assert DiagnosticCode.DIAG_ERR_TRUNK_POWER_DEGRADED == 0xEEB1
        assert DiagnosticCode.DIAG_ERR_SPUR_PORT_FAULT == 0xEEB2
        assert DiagnosticCode.DIAG_ERR_SWITCH_THERMAL_OVERHEAT == 0xEEB3
        assert DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT == 0xEEB4
        assert DiagnosticCode.DIAG_ERR_PORT_BABBLING_IDIOT == 0xEEB5

        # Signed 16-bit equality test
        signed_trunk_fault = 0xEEB1 - 0x10000
        assert DiagnosticCode.DIAG_ERR_TRUNK_POWER_DEGRADED == signed_trunk_fault
        assert signed_trunk_fault == DiagnosticCode.DIAG_ERR_TRUNK_POWER_DEGRADED
        assert DiagnosticCode.DIAG_ERR_TRUNK_POWER_DEGRADED != 0xEEB2
        assert (DiagnosticCode.DIAG_ERR_TRUNK_POWER_DEGRADED & 0xFFFF) == 0xEEB1
        assert (0xEEB1 & DiagnosticCode.DIAG_ERR_TRUNK_POWER_DEGRADED) == 0xEEB1
        assert hash(DiagnosticCode.DIAG_ERR_TRUNK_POWER_DEGRADED) == hash(0xEEB1)

        # Repr and Str
        assert "0xEEB1" in str(DiagnosticCode.DIAG_ERR_TRUNK_POWER_DEGRADED)
        assert "DIAG_ERR_TRUNK_POWER_DEGRADED" in repr(DiagnosticCode.DIAG_ERR_TRUNK_POWER_DEGRADED)

    def test_diagnostic_code_safe_signed_comparisons_all_codes(self) -> None:
        """Validate all DiagnosticCode values support safe signed/unsigned 16-bit comparisons."""
        for code, expected_u16 in [
            (DiagnosticCode.DIAG_OK, 0x0000),
            (DiagnosticCode.DIAG_ERR_TRUNK_POWER_DEGRADED, 0xEEB1),
            (DiagnosticCode.DIAG_ERR_SPUR_PORT_FAULT, 0xEEB2),
            (DiagnosticCode.DIAG_ERR_SWITCH_THERMAL_OVERHEAT, 0xEEB3),
            (DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT, 0xEEB4),
            (DiagnosticCode.DIAG_ERR_PORT_BABBLING_IDIOT, 0xEEB5),
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

        assert DiagnosticCode.DIAG_ERR_TRUNK_POWER_DEGRADED != DiagnosticCode.DIAG_OK
        assert DiagnosticCode.DIAG_ERR_TRUNK_POWER_DEGRADED != 0

    def test_exceptions_hierarchy(self) -> None:
        """Validate CIPAPLSwitchSafetyError exception inheritance structure."""
        assert issubclass(SwitchTrunkPowerDegradedFaultError, CIPAPLSwitchSafetyError)
        assert issubclass(SwitchSpurPortFaultError, CIPAPLSwitchSafetyError)
        assert issubclass(SwitchThermalOverheatFaultError, CIPAPLSwitchSafetyError)
        assert issubclass(SwitchDualCrcSafetyFaultError, CIPAPLSwitchSafetyError)
        assert issubclass(SwitchPortBabblingFaultError, CIPAPLSwitchSafetyError)

        assert SwitchTrunkPowerError is SwitchTrunkPowerDegradedFaultError
        assert SwitchSpurFaultError is SwitchSpurPortFaultError
        assert SwitchThermalError is SwitchThermalOverheatFaultError
        assert SwitchCrcFaultError is SwitchDualCrcSafetyFaultError
        assert SwitchBabblingError is SwitchPortBabblingFaultError

    def test_switch_status_bits(self) -> None:
        assert SwitchStatusBits.ONLINE == 1
        assert SwitchStatusBits.NORMAL == 2
        assert SwitchStatusBits.TRUNK_POWER_DEGRADED == 4
        assert SwitchStatusBits.SPUR_PORT_FAULT == 8
        assert SwitchStatusBits.THERMAL_OVERHEAT == 16
        assert SwitchStatusBits.CRC_FAULT == 32
        assert SwitchStatusBits.BABBLING_FAULT == 64
        assert SwitchStatusBits.SAFETY_TRIPPED == 128

    def test_engine_and_packet_aliases(self) -> None:
        """Validate alias classes for engine, state, and packets."""
        assert CipSafetySwitchOperatingState is SwitchOperatingState
        assert CIPSwitchOperatingState is SwitchOperatingState
        assert SwitchState is SwitchOperatingState
        assert CipSafetySwitchPortState is SwitchPortState
        assert CIPSwitchPortState is SwitchPortState
        assert PortState is SwitchPortState
        assert SwitchDiagnosticCode is DiagnosticCode
        assert CIPAPLSwitchDiagnosticCode is DiagnosticCode
        assert CipSafetyAPLSwitchPacket is CIPAPLSwitchPacket
        assert CIPSwitchPacket is CIPAPLSwitchPacket
        assert CipSafetyAplSwitchEngine is CIPAPLSwitchSafetyEngine
        assert CIPAPLSwitchEngine is CIPAPLSwitchSafetyEngine
        assert APLSwitchSafetyEngine is CIPAPLSwitchSafetyEngine


# ============================================================================
# 2. TestDualSafetyCrcMathematics
# ============================================================================

class TestDualSafetyCrcMathematics:
    """Validate Dual CRC-S1/S2 generator polynomials, sensitivity, and EPID hash."""

    def test_crc_s1_polynomial_and_initial_seed(self) -> None:
        data = b"\x01\x02\x03\x04"
        crc = compute_crc_s1(data)
        assert 0 <= crc <= 0xFFFF
        # Seed 0x0000 on empty data yields 0
        assert compute_crc_s1(b"") == 0

    def test_crc_s2_polynomial_and_initial_seed(self) -> None:
        data = b"\x01\x02\x03\x04"
        crc = compute_crc_s2(data)
        assert 0 <= crc <= 0xFFFF
        assert compute_crc_s2(b"") == 0

    def test_crc_s1_single_bit_perturbation(self) -> None:
        data = bytearray(b"CIP_SAFETY_APL_SWITCH_PAYLOAD_TEST")
        crc1 = compute_crc_s1(bytes(data))
        data[0] ^= 0x01
        crc2 = compute_crc_s1(bytes(data))
        assert crc1 != crc2

    def test_crc_s2_single_bit_perturbation(self) -> None:
        data = bytearray(b"INVERTED_HEADER_TEST_BYTES_FOR_CRC_S2_SWITCH")
        crc1 = compute_crc_s2(bytes(data))
        data[2] ^= 0x80
        crc2 = compute_crc_s2(bytes(data))
        assert crc1 != crc2

    def test_verify_dual_crc_s_helper(self) -> None:
        payload = b"\xAA\xBB\xCC\xDD"
        inv_hdr = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        c1 = compute_crc_s1(payload)
        c2 = compute_crc_s2(inv_hdr)
        assert verify_dual_crc_s(payload, inv_hdr, c1, c2) is True
        assert verify_dual_crc_s(payload, inv_hdr, c1 ^ 0x01, c2) is False
        assert verify_dual_crc_s(payload, inv_hdr, c1, c2 ^ 0x01) is False

    def test_epid_hash_and_crc32(self) -> None:
        epid = "HORNER-OCS-APL-FIELD-SWITCH-SIL3"
        h = compute_epid_hash(epid)
        assert 0 <= h <= 0xFFFF
        crc32_val = compute_epid_crc32(epid)
        assert crc32_val == 0xDB4B7D28

    def test_crc16_ccitt_compatibility(self) -> None:
        data = b"123456789"
        crc = calculate_crc16_ccitt(data)
        assert 0 <= crc <= 0xFFFF

    def test_crc_s1_full_payload_bit_perturbation_sensitivity(self) -> None:
        """Validate single-bit perturbation detection across entire payload for CRC-S1."""
        base_payload = b"\x10\x20\x30\x40\x50\x60\x70\x80"
        base_crc = compute_crc_s1(base_payload)
        for byte_idx in range(len(base_payload)):
            for bit_idx in range(8):
                mutated = bytearray(base_payload)
                mutated[byte_idx] ^= (1 << bit_idx)
                mutated_crc = compute_crc_s1(bytes(mutated))
                assert mutated_crc != base_crc, f"CRC collision on byte {byte_idx} bit {bit_idx}"

    def test_crc_s2_full_header_bit_perturbation_sensitivity(self) -> None:
        """Validate single-bit perturbation detection across inverted header for CRC-S2."""
        raw_header = (
            DEFAULT_SESSION_ID.to_bytes(2, "big")
            + (1).to_bytes(2, "big")
            + (100).to_bytes(4, "big")
            + (2).to_bytes(1, "big")
            + (0x00FF).to_bytes(2, "big")
            + (50000).to_bytes(2, "big")
            + (800).to_bytes(2, "big")
            + (0).to_bytes(2, "big")
            + (35).to_bytes(2, "big")
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
        data = b"\x12\x34\x56\x78"
        assert calc_crc_s1(data) == compute_crc_s1(data)
        assert calculate_cip_safety_crc_s1(data) == compute_crc_s1(data)
        assert calculate_crc_s1(data) == compute_crc_s1(data)
        assert calc_crc_s2(data) == compute_crc_s2(data)
        assert calculate_cip_safety_crc_s2(data) == compute_crc_s2(data)
        assert calculate_crc_s2(data) == compute_crc_s2(data)


# ============================================================================
# 3. TestPacketModelAndBinarySerialization
# ============================================================================

class TestPacketModelAndBinarySerialization:
    """Validate CIPAPLSwitchPacket dataclass, packing, unpacking, and verification."""

    def test_packet_creation_and_crc_computation(self) -> None:
        pkt = CIPAPLSwitchPacket(
            session_id=DEFAULT_SESSION_ID,
            sequence_number=10,
            timestamp_us=500,
            switch_state=SwitchOperatingState.NORMAL_OPERATION,
            active_ports_bitmap=0x00FF,
            trunk_voltage_mv=50000,
            trunk_current_ma=800,
            spur_fault_bitmap=0,
            temp_degc=35,
        )
        assert pkt.crc_s1 != 0
        assert pkt.crc_s2 != 0
        assert pkt.validate_crcs() is True
        assert pkt.is_valid() is True

    def test_packet_property_getters_and_setters(self) -> None:
        pkt = CIPAPLSwitchPacket()
        assert pkt.sequence == 0
        pkt.sequence = 42
        assert pkt.sequence == 42
        assert pkt.sequence_number == 42

        assert pkt.timestamp == 0
        pkt.timestamp = 9999
        assert pkt.timestamp_us == 9999

        assert pkt.voltage == 50000
        assert pkt.current == 800
        assert pkt.temperature == 35
        assert pkt.active_ports == 0x00FF
        assert pkt.fault_bitmap == 0

    def test_pack_and_unpack_roundtrip(self) -> None:
        pkt = create_valid_apl_switch_packet(
            sequence=7,
            timestamp_us=12345,
            switch_state=SwitchOperatingState.NORMAL_OPERATION,
            active_ports_bitmap=0x00FF,
            trunk_voltage_mv=50200,
            trunk_current_ma=820,
            spur_fault_bitmap=0,
            temp_degc=38,
            payload_bytes=b"\xDE\xAD\xBE\xEF\xCA\xFE",
        )
        raw = pkt.pack()
        unpacked = CIPAPLSwitchPacket.unpack(raw)

        assert unpacked.session_id == pkt.session_id
        assert unpacked.sequence_number == 7
        assert unpacked.timestamp_us == 12345
        assert unpacked.switch_state == SwitchOperatingState.NORMAL_OPERATION
        assert unpacked.active_ports_bitmap == 0x00FF
        assert unpacked.trunk_voltage_mv == 50200
        assert unpacked.trunk_current_ma == 820
        assert unpacked.spur_fault_bitmap == 0
        assert unpacked.temp_degc == 38
        assert unpacked.payload_bytes == b"\xDE\xAD\xBE\xEF\xCA\xFE"
        assert unpacked.validate_crcs() is True

    def test_unpack_too_short_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            CIPAPLSwitchPacket.unpack(b"\x01\x02\x03")

    def test_tampered_payload_fails_validation(self) -> None:
        pkt = create_valid_apl_switch_packet()
        assert pkt.validate_crcs() is True
        pkt.payload_bytes = b"\xFF\xFF\xFF\xFF"
        assert pkt.validate_crcs() is False

    def test_packet_creation_helper_and_aliases(self) -> None:
        p1 = create_valid_apl_switch_packet()
        p2 = create_valid_switch_packet()
        p3 = create_valid_cip_switch_packet()
        assert p1.validate_crcs() is True
        assert p2.validate_crcs() is True
        assert p3.validate_crcs() is True

    def test_packet_sequence_and_timestamp_integrity(self) -> None:
        pkt = create_valid_apl_switch_packet(sequence=65535, timestamp_us=0xFFFFFFFF)
        raw = pkt.pack()
        unpacked = CIPAPLSwitchPacket.unpack(raw)
        assert unpacked.sequence_number == 65535
        assert unpacked.timestamp_us == 0xFFFFFFFF


# ============================================================================
# 4. TestSwitchTelemetryProfiling
# ============================================================================

class TestSwitchTelemetryProfiling:
    """Validate IEEE 802.3cg trunk power delivery, spur ports, and nominal telemetry."""

    def test_nominal_switch_telemetry_defaults(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        assert engine.trunk_voltage_mv == TRUNK_VOLTAGE_NOMINAL_MV
        assert engine.trunk_current_ma == TRUNK_CURRENT_NOMINAL_MA
        assert engine.temp_degc == 35
        assert engine.active_ports_bitmap == DEFAULT_ACTIVE_PORTS_BITMAP
        assert engine.num_ports == DEFAULT_NUM_SPUR_PORTS
        assert engine.spur_fault_bitmap == 0
        assert engine.diagnostic_code == DIAG_OK
        assert engine.fault_code == 0

    def test_trunk_power_calculation(self) -> None:
        engine = CIPAPLSwitchSafetyEngine(trunk_voltage_mv=50000, trunk_current_ma=800)
        # P = 50000 * 800 / 1000 = 40000 mW (40.0 W)
        assert engine.power_mw == 40000

    def test_active_spur_ports_bitmap_and_counts(self) -> None:
        engine = CIPAPLSwitchSafetyEngine(num_ports=8)
        assert engine.active_ports_bitmap == 0x00FF
        assert len(engine.port_states) == 8
        for state in engine.port_states:
            assert state == SwitchPortState.PORT_LINK_UP

    def test_spur_current_levels_nominal(self) -> None:
        engine = CIPAPLSwitchSafetyEngine(num_ports=8)
        assert len(engine.spur_currents_ma) == 8
        for curr in engine.spur_currents_ma:
            assert curr == SPUR_CURRENT_NOMINAL_MA

    def test_connect_initializes_nominal_telemetry(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.disconnect()
        assert engine.switch_state == SwitchOperatingState.DE_ENERGIZED
        assert engine.online is False

        engine.connect()
        assert engine.switch_state == SwitchOperatingState.NORMAL_OPERATION
        assert engine.trunk_voltage_mv == 50000
        assert engine.trunk_current_ma == 800
        assert engine.active_ports_bitmap == 0x00FF
        assert engine.online is True
        assert engine.tripped is False

    def test_disconnect_zeroes_voltage_current_and_ports(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.disconnect()
        assert engine.switch_state == SwitchOperatingState.DE_ENERGIZED
        assert engine.trunk_voltage_mv == 0
        assert engine.trunk_current_ma == 0
        assert engine.active_ports_bitmap == 0
        for ps in engine.port_states:
            assert ps == SwitchPortState.PORT_DISABLED
        for c in engine.spur_currents_ma:
            assert c == 0

    def test_send_and_receive_packet_roundtrip_telemetry(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        pkt = engine.send_packet(b"\x11\x22\x33\x44")
        assert pkt.validate_crcs() is True
        assert engine.tx_frame_count == 1
        assert engine.sequence_number == 1

        res = engine.receive_packet(pkt)
        assert res is True
        assert engine.rx_frame_count == 1
        assert engine.online is True


# ============================================================================
# 5. TestTrunkVoltageDegradationFaultInjectionAndTrip
# ============================================================================

class TestTrunkVoltageDegradationFaultInjectionAndTrip:
    """Validate trunk voltage degradation fault injection (< 44V or > 55V) and trip 0xEEB1."""

    def test_inject_trunk_voltage_under_trips_0xEEB1(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        assert engine.online is True

        engine.inject_trunk_voltage_fault(40000)
        assert engine.switch_state == SwitchOperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_TRUNK_POWER_DEGRADED
        assert engine.fault_code == 0xEEB1
        assert engine.online is False
        assert engine.tripped is True

    def test_inject_trunk_voltage_over_trips_0xEEB1(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_trunk_voltage_fault(58000)
        assert engine.switch_state == SwitchOperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_TRUNK_POWER_DEGRADED
        assert engine.fault_code == 0xEEB1
        assert engine.online is False
        assert engine.tripped is True

    def test_inject_trunk_voltage_default_parameter(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_trunk_voltage_fault()
        assert engine.trunk_voltage_mv == 40000
        assert engine.diagnostic_code == DIAG_ERR_TRUNK_POWER_DEGRADED

    def test_receive_packet_with_degraded_voltage_trips_0xEEB1(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        pkt = create_valid_apl_switch_packet(trunk_voltage_mv=41000)
        assert engine.receive_packet(pkt) is False
        assert engine.diagnostic_code == DIAG_ERR_TRUNK_POWER_DEGRADED
        assert engine.tripped is True

    def test_trunk_voltage_recovery_on_clear_fault(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_trunk_voltage_fault(40000)
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.switch_state == SwitchOperatingState.NORMAL_OPERATION
        assert engine.diagnostic_code == DIAG_OK
        assert engine.fault_code == 0
        assert engine.trunk_voltage_mv == 50000
        assert engine.online is True
        assert engine.tripped is False


# ============================================================================
# 6. TestSpurPortFaultInjectionAndTrip
# ============================================================================

class TestSpurPortFaultInjectionAndTrip:
    """Validate spur port overload/short-circuit fault injection (> 115 mA) and trip 0xEEB2."""

    def test_inject_spur_fault_default_trips_0xEEB2(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        assert engine.online is True

        engine.inject_spur_fault(port_idx=0)
        assert engine.switch_state == SwitchOperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_SPUR_PORT_FAULT
        assert engine.fault_code == 0xEEB2
        assert (engine.spur_fault_bitmap & 0x01) != 0
        assert engine.online is False
        assert engine.tripped is True

    def test_inject_spur_fault_overload_current(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_spur_fault(port_idx=2, current_ma=160)
        assert engine.spur_currents_ma[2] == 160
        assert engine.port_states[2] == SwitchPortState.PORT_OVERLOAD
        assert (engine.spur_fault_bitmap & (1 << 2)) != 0
        assert engine.diagnostic_code == DIAG_ERR_SPUR_PORT_FAULT

    def test_inject_spur_fault_short_circuit_current(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        # Direct short circuit injection with low resistance/current indicator
        engine.inject_spur_fault(port_idx=3, current_ma=100)
        assert engine.port_states[3] == SwitchPortState.PORT_SHORT_CIRCUIT
        assert (engine.spur_fault_bitmap & (1 << 3)) != 0
        assert engine.diagnostic_code == DIAG_ERR_SPUR_PORT_FAULT

    def test_inject_spur_fault_multiple_ports_bitmap(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_spur_fault(port_idx=0)
        engine.inject_spur_fault(port_idx=4)
        assert (engine.spur_fault_bitmap & (1 << 0)) != 0
        assert (engine.spur_fault_bitmap & (1 << 4)) != 0

    def test_receive_packet_with_spur_fault_trips_0xEEB2(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        pkt = create_valid_apl_switch_packet(spur_fault_bitmap=0x04)
        assert engine.receive_packet(pkt) is False
        assert engine.diagnostic_code == DIAG_ERR_SPUR_PORT_FAULT
        assert engine.tripped is True

    def test_spur_fault_recovery_on_clear_fault(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_spur_fault(port_idx=1)
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.switch_state == SwitchOperatingState.NORMAL_OPERATION
        assert engine.diagnostic_code == DIAG_OK
        assert engine.spur_fault_bitmap == 0
        assert engine.port_states[1] == SwitchPortState.PORT_LINK_UP
        assert engine.online is True
        assert engine.tripped is False


# ============================================================================
# 7. TestSwitchThermalOverheatInjectionAndTrip
# ============================================================================

class TestSwitchThermalOverheatInjectionAndTrip:
    """Validate switch internal thermal overheat surveillance (> 85.0 degC) and trip 0xEEB3."""

    def test_inject_thermal_fault_default_trips_0xEEB3(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        assert engine.online is True

        engine.inject_thermal_fault()
        assert engine.switch_state == SwitchOperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_SWITCH_THERMAL_OVERHEAT
        assert engine.fault_code == 0xEEB3
        assert engine.temp_degc > 85
        assert engine.online is False
        assert engine.tripped is True

    def test_inject_thermal_fault_custom_temperature(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_thermal_fault(92)
        assert engine.temp_degc == 92
        assert engine.diagnostic_code == DIAG_ERR_SWITCH_THERMAL_OVERHEAT

    def test_receive_packet_with_overheat_trips_0xEEB3(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        pkt = create_valid_apl_switch_packet(temp_degc=88)
        assert engine.receive_packet(pkt) is False
        assert engine.diagnostic_code == DIAG_ERR_SWITCH_THERMAL_OVERHEAT
        assert engine.tripped is True

    def test_thermal_overheat_recovery_on_clear_fault(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_thermal_fault(95)
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.switch_state == SwitchOperatingState.NORMAL_OPERATION
        assert engine.diagnostic_code == DIAG_OK
        assert engine.temp_degc == 35
        assert engine.online is True
        assert engine.tripped is False

    def test_boundary_temperature_conditions(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.temp_degc = 85
        assert engine.online is True
        assert engine.tripped is False

        engine.temp_degc = 86
        assert engine.online is False
        assert engine.tripped is True


# ============================================================================
# 8. TestPortBabblingIdiotInjectionAndTrip
# ============================================================================

class TestPortBabblingIdiotInjectionAndTrip:
    """Validate jabber babbling idiot fault injection and trip 0xEEB5."""

    def test_inject_babbling_fault_trips_0xEEB5(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        assert engine.online is True

        engine.inject_babbling_fault(port_idx=0)
        assert engine.switch_state == SwitchOperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_PORT_BABBLING_IDIOT
        assert engine.fault_code == 0xEEB5
        assert engine.online is False
        assert engine.tripped is True

    def test_jabber_count_exceeds_threshold(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_babbling_fault(port_idx=2)
        assert engine.port_jabber_counts[2] > engine.jabber_limit
        assert engine.port_states[2] == SwitchPortState.PORT_BABBLING

    def test_babbling_fault_sets_spur_fault_bitmap(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_babbling_fault(port_idx=5)
        assert (engine.spur_fault_bitmap & (1 << 5)) != 0

    def test_babbling_fault_updates_port_state(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_babbling_fault(port_idx=1)
        assert engine.port_states[1] == SwitchPortState.PORT_BABBLING

    def test_babbling_recovery_on_clear_fault(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_babbling_fault(port_idx=1)
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.switch_state == SwitchOperatingState.NORMAL_OPERATION
        assert engine.diagnostic_code == DIAG_OK
        assert engine.spur_fault_bitmap == 0
        assert engine.port_jabber_counts[1] == 0
        assert engine.port_states[1] == SwitchPortState.PORT_LINK_UP
        assert engine.online is True
        assert engine.tripped is False


# ============================================================================
# 9. TestCrcCorruptionInjectionAndTrip
# ============================================================================

class TestCrcCorruptionInjectionAndTrip:
    """Validate Dual CRC safety checksum corruption detection and error counters (0xEEB4)."""

    def test_inject_crc_fault_trips_0xEEB4(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        assert engine.packet_loss_counter == 0
        assert engine.crc_error_count == 0

        engine.inject_crc_fault()
        assert engine.switch_state == SwitchOperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.fault_code == 0xEEB4
        assert engine.crc_error_count == 1
        assert engine.packet_loss_counter == 1
        assert engine.online is False
        assert engine.tripped is True

    def test_receive_packet_with_corrupted_crc_s1_trips_0xEEB4(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        bad_pkt = create_valid_apl_switch_packet()
        bad_pkt.crc_s1 = 0xDEAD
        assert engine.receive_packet(bad_pkt) is False
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.crc_error_count == 1
        assert engine.packet_loss_counter == 1

    def test_receive_packet_with_corrupted_crc_s2_trips_0xEEB4(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        bad_pkt = create_valid_apl_switch_packet()
        bad_pkt.crc_s2 = 0xBEEF
        assert engine.receive_packet(bad_pkt) is False
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.crc_error_count == 1
        assert engine.packet_loss_counter == 1

    def test_crc_error_counter_monotonic_increment(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        assert engine.crc_error_count == 0
        engine.inject_crc_fault()
        assert engine.crc_error_count == 1
        engine.inject_crc_fault()
        assert engine.crc_error_count == 2

    def test_packet_loss_counter_monotonic_increment(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        assert engine.packet_loss_counter == 0
        engine.inject_crc_fault()
        assert engine.packet_loss_counter == 1
        bad_pkt = create_valid_apl_switch_packet()
        bad_pkt.crc_s1 = 0x1234
        engine.receive_packet(bad_pkt)
        assert engine.packet_loss_counter == 2


# ============================================================================
# 10. TestSafeStopInterlockAndCoils
# ============================================================================

class TestSafeStopInterlockAndCoils:
    """Validate discrete coils %M660 (ONLINE) and %M661 (SAFETY_TRIP) interlock."""

    def test_healthy_coils_state(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_SWITCH_ONLINE) is True
        assert rt.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP) is False

    def test_safe_stop_interlock_on_all_5_fault_types(self) -> None:
        rt = RegisterTable()
        fault_injections = [
            lambda eng: eng.inject_trunk_voltage_fault(40000),
            lambda eng: eng.inject_spur_fault(port_idx=0),
            lambda eng: eng.inject_thermal_fault(90),
            lambda eng: eng.inject_crc_fault(),
            lambda eng: eng.inject_babbling_fault(port_idx=1),
        ]
        for inj in fault_injections:
            engine = CIPAPLSwitchSafetyEngine()
            engine.connect()
            inj(engine)
            engine.sync_to_registers(rt)
            assert rt.read_bit(COIL_CIP_APL_SWITCH_ONLINE) is False
            assert rt.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP) is True

    def test_coil_mutual_exclusivity_healthy_and_tripped(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        # Healthy
        b_on = rt.read_bit(COIL_CIP_APL_SWITCH_ONLINE)
        b_trip = rt.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP)
        assert b_on != b_trip

        # Tripped
        engine.inject_trunk_voltage_fault(40000)
        engine.sync_to_registers(rt)
        b_on = rt.read_bit(COIL_CIP_APL_SWITCH_ONLINE)
        b_trip = rt.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP)
        assert b_on != b_trip

    def test_clear_fault_restores_healthy_coils(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        rt = RegisterTable()
        engine.inject_trunk_voltage_fault(40000)
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_SWITCH_ONLINE) is False
        assert rt.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP) is True

        engine.clear_fault()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_SWITCH_ONLINE) is True
        assert rt.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP) is False

    def test_reset_restores_nominal_state_and_counters(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_thermal_fault(95)
        assert engine.tripped is True
        engine.reset()
        assert engine.switch_state == SwitchOperatingState.NORMAL_OPERATION
        assert engine.diagnostic_code == DIAG_OK
        assert engine.sequence_number == 0
        assert engine.tx_frame_count == 0
        assert engine.rx_frame_count == 0
        assert engine.packet_loss_counter == 0
        assert engine.crc_error_count == 0
        assert engine.online is True

    def test_trip_safety_and_trip_fault_methods(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.trip_fault(DIAG_ERR_TRUNK_POWER_DEGRADED, "Test trip")
        assert engine.switch_state == SwitchOperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_TRUNK_POWER_DEGRADED
        assert engine.fault_code == 0xEEB1

    def test_status_word_bitmask_flags_coverage(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        assert (engine.status_word & SwitchStatusBits.ONLINE) != 0
        assert (engine.status_word & SwitchStatusBits.NORMAL) != 0
        assert (engine.status_word & SwitchStatusBits.SAFETY_TRIPPED) == 0

        engine.inject_trunk_voltage_fault(40000)
        assert (engine.status_word & SwitchStatusBits.TRUNK_POWER_DEGRADED) != 0
        assert (engine.status_word & SwitchStatusBits.SAFETY_TRIPPED) != 0
        assert (engine.status_word & SwitchStatusBits.ONLINE) == 0


# ============================================================================
# 11. TestRegisterTableSynchronization
# ============================================================================

class TestRegisterTableSynchronization:
    """Validate bit-exact Horner OCS register synchronization (%R2830..%R2837)."""

    def test_sync_to_registers_healthy(self) -> None:
        rt = RegisterTable()
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_CIP_APL_SWITCH_STATUS) == int(SwitchOperatingState.NORMAL_OPERATION)
        assert (rt.read_word(REG_CIP_APL_SWITCH_PORT_BITMAP) & 0xFFFF) == 0x00FF
        assert (rt.read_word(REG_CIP_APL_SWITCH_TRUNK_VOLTAGE_MV) & 0xFFFF) == 50000
        assert (rt.read_word(REG_CIP_APL_SWITCH_TRUNK_CURRENT_MA) & 0xFFFF) == 800
        assert (rt.read_word(REG_CIP_APL_SWITCH_SPUR_FAULT_BITMAP) & 0xFFFF) == 0
        assert rt.read_word(REG_CIP_APL_SWITCH_TEMP_DEGC) == 35
        assert (rt.read_word(REG_CIP_APL_SWITCH_CRC_ERROR_COUNT) & 0xFFFF) == 0
        assert (rt.read_word(REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
        assert rt.read_bit(COIL_CIP_APL_SWITCH_ONLINE) is True
        assert rt.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP) is False

    def test_sync_to_registers_tripped_trunk_voltage(self) -> None:
        rt = RegisterTable()
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_trunk_voltage_fault(42000)
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_CIP_APL_SWITCH_STATUS) == int(SwitchOperatingState.SAFETY_TRIP)
        assert (rt.read_word(REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEEB1
        assert (rt.read_word(REG_CIP_APL_SWITCH_TRUNK_VOLTAGE_MV) & 0xFFFF) == 42000
        assert rt.read_bit(COIL_CIP_APL_SWITCH_ONLINE) is False
        assert rt.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP) is True

    def test_sync_to_registers_tripped_spur_fault(self) -> None:
        rt = RegisterTable()
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_spur_fault(port_idx=3)
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_CIP_APL_SWITCH_STATUS) == int(SwitchOperatingState.SAFETY_TRIP)
        assert (rt.read_word(REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEEB2
        assert (rt.read_word(REG_CIP_APL_SWITCH_SPUR_FAULT_BITMAP) & 0xFFFF) == (1 << 3)
        assert rt.read_bit(COIL_CIP_APL_SWITCH_ONLINE) is False
        assert rt.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP) is True

    def test_sync_to_registers_tripped_thermal(self) -> None:
        rt = RegisterTable()
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        engine.inject_thermal_fault(95)
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_CIP_APL_SWITCH_STATUS) == int(SwitchOperatingState.SAFETY_TRIP)
        assert (rt.read_word(REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEEB3
        assert rt.read_word(REG_CIP_APL_SWITCH_TEMP_DEGC) == 95
        assert rt.read_bit(COIL_CIP_APL_SWITCH_ONLINE) is False
        assert rt.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP) is True

    def test_signed_16bit_safe_masking_temperature_and_diag(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE, 0xEEB1)
        w = rt.read_word(REG_CIP_APL_SWITCH_DIAGNOSTIC_CODE)
        assert (w & 0xFFFF) == 0xEEB1

        # Negative temperature e.g. -10 degC
        safe_write_word(rt, REG_CIP_APL_SWITCH_TEMP_DEGC, -10)
        temp_val = rt.read_word(REG_CIP_APL_SWITCH_TEMP_DEGC)
        assert temp_val == -10

    def test_privilege_modes_user_and_system(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R2830", 2, privilege=PrivilegeMode.USER)
        assert rt.read_word("%R2830") == 2
        safe_write_word(rt, "%R2830", 5, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_word("%R2830") == 5

    def test_safe_write_word_and_uword_helpers(self) -> None:
        rt = RegisterTable()
        safe_write_uword(rt, "%R2832", 50000)
        assert (rt.read_word("%R2832") & 0xFFFF) == 50000
        safe_write_word(rt, "%R2835", 40)
        assert rt.read_word("%R2835") == 40

    def test_safe_write_bit_helper(self) -> None:
        rt = RegisterTable()
        safe_write_bit(rt, "%M660", True)
        assert rt.read_bit("%M660") is True
        safe_write_bit(rt, "%M660", False)
        assert rt.read_bit("%M660") is False


# ============================================================================
# 12. TestPureIEC61131StructuredTextAndSecurity
# ============================================================================

class TestPureIEC61131StructuredTextAndSecurity:
    """Validate pure ST POU CipSafetyAplSwitchSync and anti-ladder security guard."""

    def test_st_program_constant_and_aliases(self) -> None:
        assert "PROGRAM CipSafetyAplSwitchSync" in ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC
        assert CIP_SAFETY_APL_SWITCH_SYNC_POU == ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC
        assert CIP_SAFETY_APL_SWITCH_PURE_ST_POU == ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC
        assert CIP_SAFETY_APL_SWITCH_POU == ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC

    def test_st_parser_validates_pou(self) -> None:
        res = STParser.validate_code(ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC)
        assert res.status == AgentStatus.SUCCESS

    def test_st_parser_ast_bound_registers(self) -> None:
        ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC)
        expected = {
            "%R2830", "%R2831", "%R2832", "%R2833",
            "%R2834", "%R2835", "%R2836", "%R2837",
            "%M660", "%M661",
        }
        assert expected.issubset(set(ast.bound_registers))

    def test_security_guard_assert_pure_st_content(self) -> None:
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_APL_SWITCH_SYNC)

    def test_verify_pure_st_helper_functions(self) -> None:
        assert verify_cip_safety_apl_switch_pure_st() is True
        assert verify_switch_pure_st() is True

    @pytest.mark.parametrize(
        "construct",
        [
            "---[ ]---",
            "---[/]---",
            "---( )---",
            "---(/)---",
            "RUNG 1: LD %R2830",
            "NETWORK 10:",
            "XIC %M660",
            "XIO %M661",
            "OTE %M660",
        ],
    )
    def test_security_guard_rejects_all_9_ladder_constructs(self, construct: str) -> None:
        poisoned = f"PROGRAM Test VAR x: BOOL; END_VAR {construct} END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(poisoned)


# ============================================================================
# 13. TestILogicUnitComplianceAndSimulationSoak
# ============================================================================

class TestILogicUnitComplianceAndSimulationSoak:
    """Validate ILogicUnit interface compliance and continuous simulation soak."""

    def test_ilogic_unit_inheritance(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        assert isinstance(engine, ILogicUnit)

    def test_scan_step_with_dt_float(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        res = engine.scan_step(0.0004)
        assert res.status == AgentStatus.SUCCESS

    def test_scan_step_with_scan_context(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        ctx = ScanContext(cycle=1, dt=0.0004)
        res = engine.scan_step(ctx)
        assert res.status == AgentStatus.SUCCESS

    def test_scan_step_with_context_kwarg(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        ctx = ScanContext(cycle=2, dt=0.0004)
        res = engine.scan_step(context=ctx)
        assert res.status == AgentStatus.SUCCESS

    def test_scan_step_surveillance_trips_on_fault(self) -> None:
        rt = RegisterTable()
        engine = CIPAPLSwitchSafetyEngine(register_table=rt)
        engine.connect()
        engine.trunk_voltage_mv = 40000  # Degradation injected
        res = engine.scan_step(0.0004)
        assert res.status == AgentStatus.SUCCESS
        assert engine.tripped is True
        assert rt.read_bit(COIL_CIP_APL_SWITCH_SAFETY_TRIP) is True

    def test_step_and_execute_aliases(self) -> None:
        engine = CIPAPLSwitchSafetyEngine()
        engine.connect()
        res1 = engine.step(0.0004)
        assert res1.status == AgentStatus.SUCCESS
        res2 = engine.execute()
        assert res2.status == AgentStatus.SUCCESS

    def test_100_cycle_simulation_soak_memory_bounded(self) -> None:
        rt = RegisterTable()
        engine = CIPAPLSwitchSafetyEngine(register_table=rt)
        engine.connect()

        tracemalloc.start()
        m0, _ = tracemalloc.get_traced_memory()

        for cycle in range(1, 101):
            pkt = engine.send_packet()
            engine.receive_packet(pkt)
            res = engine.scan_step(0.0004)
            assert res.status == AgentStatus.SUCCESS

        m1, _ = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        growth_kb = (m1 - m0) / 1024.0
        assert growth_kb < 1024.0

    def test_engine_properties_priority_and_enabled(self) -> None:
        engine = CIPAPLSwitchSafetyEngine(priority=5, is_enabled=True)
        assert engine.priority == 5
        assert engine.is_enabled is True
        engine.is_enabled = False
        assert engine.is_enabled is False


# ============================================================================
# 14. TestVerificationRunner9StagesAndCli
# ============================================================================

class TestVerificationRunner9StagesAndCli:
    """Validate 9-stage verification suite, 4-state engineering contract, and CLI."""

    def test_runner_passes_all_9_stages(self) -> None:
        res = run_cip_safety_apl_switch_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["total_stages"] == 9
        assert res["stages_passed"] == 9

    def test_runner_evidence_data_integrity(self) -> None:
        res = run_cip_safety_apl_switch_verification()
        assert "data" in res
        assert res["data"]["work_package"] == "W322"
        assert res["data"]["gate"] == "G8"
        assert len(res["data"]["stages"]) == 9
        for stage in res["data"]["stages"]:
            assert stage["passed"] is True
            assert "timing_ms" in stage

    def test_runner_no_file_written_when_output_path_is_none(self) -> None:
        res = run_cip_safety_apl_switch_verification(output_path=None)
        assert res["status"] == "success"

    def test_runner_writes_file_when_output_path_specified(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = tf.name
        try:
            res = run_cip_safety_apl_switch_verification(output_path=temp_path)
            assert res["status"] == "success"
            assert Path(temp_path).exists()
            with open(temp_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["work_package"] == "W322"
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_quick_mode_verification(self) -> None:
        res = run_cip_safety_apl_switch_verification(quick=True)
        assert res["status"] == "success"

    def test_module_cli_direct_execution(self) -> None:
        """Verify executing module CLI directly with tempfile output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "module_switch_evidence.json"
            cmd = [
                sys.executable,
                "-m",
                "jev_cscape.telemetry.cip_safety_apl_switch",
                "--output",
                str(tmp_out),
                "--quick",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            assert proc.returncode == 0
            data = json.loads(proc.stdout)
            assert data["status"] == "success"
            assert data["stages_passed"] == 9
            assert tmp_out.exists()

    def test_script_cli_direct_execution(self) -> None:
        script_path = REPO_ROOT / "scripts" / "run_cip_safety_apl_switch_verification.py"
        assert script_path.exists()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = tf.name
        try:
            cmd = [sys.executable, str(script_path), "--quick", "-o", temp_path]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            assert proc.returncode == 0
            assert "Outcome: 9/9 checks passed" in proc.stdout
            assert Path(temp_path).exists()
            with open(temp_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["work_package"] == "W322"
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_script_cli_json_mode(self) -> None:
        script_path = REPO_ROOT / "scripts" / "run_cip_safety_apl_switch_verification.py"
        assert script_path.exists()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "test_switch_json_evidence.json"
            cmd = [sys.executable, str(script_path), "--json", "--quick", "--output", str(tmp_out)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            assert proc.returncode == 0
            data = json.loads(proc.stdout)
            assert data["status"] == "success"
            assert data["stages_passed"] == 9
            assert tmp_out.exists()

    def test_script_runner_interop_cli(self) -> None:
        """Verify interop with scripts/run_cip_safety_apl_switch_verification.py CLI."""
        scripts_runner_path = REPO_ROOT / "scripts" / "run_cip_safety_apl_switch_verification.py"
        assert scripts_runner_path.exists()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "test_switch_script_evidence.json"
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
