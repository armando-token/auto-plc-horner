"""Comprehensive Unit Test Suite for Wave W319 CIP Safety Over Ethernet-APL IS Barrier Engine.

Work Package: W319 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Ethernet-APL Intrinsic Safety Power Barrier Monitor Engine.

Covers Comprehensive Deterministic Unit Tests across 14 Mandatory Test Classes (80+ Tests):
1. TestProtocolConstantsEnumsAndDiagnostics: Canonical registers (%R2800..%R2807), coils (%M653..%M654),
   aliases, protocol constants, enums (BarrierProfile, BarrierOperatingState, BarrierStatusBits),
   and signed 16-bit safe comparisons for DiagnosticCode (0x0000, 0xEEA1..0xEEA5).
2. TestDualSafetyCrcMathematics: CRC-S1 (poly 0x5935, init 0x0000) and CRC-S2 (poly 0x755B, init 0x0000)
   polynomial mathematics, single-bit perturbation detection, EPID hashing and CRC32.
3. TestPacketModelAndBinarySerialization: CIPAPLBarrierPacket dataclass, property accessors,
   inverted header computation, CRC validation, binary pack/unpack roundtrip, and tampering detection.
4. TestBarrierProfilesAndPowerCalculation: 3 barrier profiles (2-WISE, APL Trunk, Spur Field),
   voltage boundaries, current limits, max power limits, and electrical formula P = V * I / 1000.
5. TestOvervoltageInjectionAndTrip: Overvoltage injection exceeding IS limit (0xEEA1),
   transition to SAFETY_TRIP, de-assertion of online, assertion of tripped, and recovery.
6. TestOvercurrentExcursionAndTrip: Overcurrent excursion exceeding IS limit (0xEEA2),
   transition to SAFETY_TRIP, status bit assertion, and fail-safe trip.
7. TestThermalBarrierOverheatAndTrip: Barrier thermal overheat exceeding limit > 85.0 degC (0xEEA3),
   transition to SAFETY_TRIP, status bit assertion, and fail-safe trip.
8. TestShieldLeakageFaultAndTrip: Shield leakage current fault exceeding limit > 50 uA (0xEEA5),
   transition to SAFETY_TRIP, status bit assertion, and fail-safe trip.
9. TestCrcCorruptionInjectionAndTrip: Dual CRC corruption injection (0xEEA4), packet corruption detection,
   and monotonic packet loss counter increments.
10. TestSafeStopInterlockAndCoils: Fail-safe interlock asserting %M654 (SAFETY_TRIP) and de-asserting %M653 (ONLINE)
    across all diagnostic trip conditions, coil mutual exclusivity, and healthy restoration upon clear_fault().
11. TestHornerRegisterTableSynchronization: Bit-exact synchronization to Horner OCS registers (%R2800..%R2807)
    and coils (%M653..%M654), status register packing, signed 16-bit masking, privilege modes, and write helpers.
12. TestPureIEC61131StructuredTextAndSecurity: Pure IEC 61131-3 ST POU CipSafetyAplBarrierSync validation
    via STParser and SecurityGuard, AST bound registers, and strict interception of 9 ladder logic constructs.
13. TestILogicUnitComplianceAndSimulationSoak: ILogicUnit interface compliance, variable scan_step argument
    handling, step/execute/reset methods, and 100-cycle continuous simulation soak with bounded memory.
14. TestVerificationRunner9StagesAndCli: Complete 9-stage verification suite run_cip_safety_apl_barrier_verification,
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
from jev_cscape.telemetry.cip_safety_apl_barrier import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_APL_BARRIER_CLASS_ID,
    CIP_APL_BARRIER_CLASS_ID,
    DEFAULT_BARRIER_IMPEDANCE_MOHM,
    NOMINAL_BARRIER_IMPEDANCE_MOHM,
    MAX_ALLOWED_BARRIER_IMPEDANCE_MOHM,
    DEFAULT_SHIELD_LEAKAGE_THRESHOLD_UA,
    MAX_SHIELD_LEAKAGE_UA,
    DEFAULT_THERMAL_LIMIT_DEGC,
    MAX_BARRIER_TEMP_DEGC,
    LIMIT_2WISE_VOLTAGE_MAX_MV,
    LIMIT_2WISE_CURRENT_MAX_MA,
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
    REG_CIP_APL_BARRIER_STATUS,
    REG_CIP_APL_BARRIER_VOLTAGE_IN_MV,
    REG_CIP_APL_BARRIER_VOLTAGE_OUT_MV,
    REG_CIP_APL_BARRIER_CURRENT_MA,
    REG_CIP_APL_BARRIER_IMPEDANCE_MOHM,
    REG_CIP_APL_BARRIER_TEMP_DEGC,
    REG_CIP_APL_BARRIER_POWER_MW,
    REG_CIP_APL_BARRIER_DIAGNOSTIC_CODE,
    COIL_CIP_APL_BARRIER_ONLINE,
    COIL_CIP_APL_BARRIER_SAFETY_TRIP,
    REG_APL_BARRIER_STATUS,
    REG_BARRIER_STATUS,
    REG_BARRIER_STATE,
    REG_CIP_APL_BARRIER_STATE,
    REG_APL_BARRIER_VOLTAGE_IN_MV,
    REG_APL_BARRIER_VOLTAGE_IN,
    REG_CIP_APL_BARRIER_VOLTAGE_IN,
    REG_APL_BARRIER_VOLTAGE_OUT_MV,
    REG_APL_BARRIER_VOLTAGE_OUT,
    REG_CIP_APL_BARRIER_VOLTAGE_OUT,
    REG_APL_BARRIER_CURRENT_MA,
    REG_APL_BARRIER_CURRENT,
    REG_CIP_APL_BARRIER_CURRENT,
    REG_APL_BARRIER_IMPEDANCE_MOHM,
    REG_APL_BARRIER_IMPEDANCE,
    REG_CIP_APL_BARRIER_IMPEDANCE,
    REG_APL_BARRIER_TEMP_DEGC,
    REG_APL_BARRIER_TEMP,
    REG_CIP_APL_BARRIER_TEMP,
    REG_APL_BARRIER_POWER_MW,
    REG_APL_BARRIER_POWER,
    REG_CIP_APL_BARRIER_POWER,
    REG_APL_BARRIER_DIAGNOSTIC_CODE,
    REG_APL_BARRIER_DIAG_CODE,
    REG_BARRIER_DIAGNOSTIC_CODE,
    COIL_APL_BARRIER_ONLINE,
    COIL_BARRIER_ONLINE,
    COIL_CIP_APL_BARRIER_HEALTHY,
    COIL_APL_BARRIER_HEALTHY,
    COIL_CIP_APL_BARRIER_ACTIVE,
    COIL_APL_BARRIER_ACTIVE,
    COIL_APL_BARRIER_SAFETY_TRIP,
    COIL_BARRIER_SAFETY_TRIP,
    COIL_CIP_APL_BARRIER_TRIP,
    COIL_APL_BARRIER_TRIP,
    COIL_CIP_APL_BARRIER_FAULT,
    COIL_APL_BARRIER_FAULT,
    BarrierOperatingState,
    CipSafetyBarrierOperatingState,
    CIPBarrierOperatingState,
    BarrierState,
    CipSafetyBarrierState,
    CIPBarrierState,
    APLBarrierState,
    BarrierProfile,
    CipSafetyBarrierProfile,
    CIPBarrierProfile,
    APLBarrierProfile,
    BARRIER_PROFILE_SPECS,
    DiagnosticCode,
    DIAG_OK,
    DIAG_ERR_OVERVOLTAGE_BARRIER,
    DIAG_ERR_OVERCURRENT_EXCURSION,
    DIAG_ERR_THERMAL_BARRIER_OVERHEAT,
    DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
    DIAG_ERR_LEAKAGE_TO_SHIELD_FAULT,
    DIAG_OVERVOLTAGE,
    DIAG_OVERCURRENT,
    DIAG_THERMAL_OVERHEAT,
    DIAG_THERMAL,
    DIAG_CRC_FAULT,
    DIAG_LEAKAGE_FAULT,
    DIAG_SHIELD_LEAKAGE,
    BarrierDiagnosticCode,
    CIPAPLBarrierDiagnosticCode,
    CipSafetyBarrierDiagnosticCode,
    APLBarrierDiagnosticCode,
    DiagnosticStatusCode,
    BarrierFaultCode,
    BarrierStatusBits,
    CipSafetyBarrierStatusBits,
    CIPBarrierStatusBits,
    APLBarrierStatusBits,
    CIPAPLBarrierSafetyError,
    BarrierOvervoltageFaultError,
    BarrierOvercurrentFaultError,
    BarrierThermalOverheatFaultError,
    BarrierDualCrcSafetyFaultError,
    BarrierShieldLeakageFaultError,
    BarrierOvervoltageError,
    BarrierOvercurrentError,
    BarrierThermalError,
    BarrierCrcFaultError,
    BarrierLeakageError,
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
    CIPAPLBarrierPacket,
    CipSafetyAPLBarrierPacket,
    CIPBarrierPacket,
    APLBarrierPacket,
    CipSafetyBarrierPacket,
    BarrierPacket,
    create_valid_apl_barrier_packet,
    create_valid_barrier_packet,
    create_valid_cip_barrier_packet,
    ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC,
    CIP_SAFETY_APL_BARRIER_SYNC_POU,
    CIP_SAFETY_APL_BARRIER_PURE_ST_POU,
    CIP_SAFETY_APL_BARRIER_POU,
    PURE_ST_POU,
    CipSafetyAplBarrierSync,
    CipSafetyAplBarrierSyncPOU,
    verify_cip_safety_apl_barrier_pure_st,
    verify_barrier_pure_st,
    CIPAPLBarrierSafetyEngine,
    CipSafetyAplBarrierEngine,
    CIPAPLBarrierEngine,
    APLBarrierSafetyEngine,
    APLBarrierEngine,
    BarrierSafetyEngine,
    run_cip_safety_apl_barrier_verification,
)


# ============================================================================
# 1. TestProtocolConstantsEnumsAndDiagnostics
# ============================================================================

class TestProtocolConstantsEnumsAndDiagnostics:
    """Validate canonical registers, coils, aliases, protocol constants, and safe comparisons."""

    def test_canonical_registers_and_coils(self) -> None:
        assert REG_CIP_APL_BARRIER_STATUS == "%R2800"
        assert REG_CIP_APL_BARRIER_VOLTAGE_IN_MV == "%R2801"
        assert REG_CIP_APL_BARRIER_VOLTAGE_OUT_MV == "%R2802"
        assert REG_CIP_APL_BARRIER_CURRENT_MA == "%R2803"
        assert REG_CIP_APL_BARRIER_IMPEDANCE_MOHM == "%R2804"
        assert REG_CIP_APL_BARRIER_TEMP_DEGC == "%R2805"
        assert REG_CIP_APL_BARRIER_POWER_MW == "%R2806"
        assert REG_CIP_APL_BARRIER_DIAGNOSTIC_CODE == "%R2807"
        assert COIL_CIP_APL_BARRIER_ONLINE == "%M653"
        assert COIL_CIP_APL_BARRIER_SAFETY_TRIP == "%M654"

    def test_register_and_coil_aliases(self) -> None:
        assert REG_APL_BARRIER_STATUS == "%R2800"
        assert REG_BARRIER_STATUS == "%R2800"
        assert REG_BARRIER_STATE == "%R2800"
        assert REG_CIP_APL_BARRIER_STATE == "%R2800"
        assert REG_APL_BARRIER_VOLTAGE_IN_MV == "%R2801"
        assert REG_APL_BARRIER_VOLTAGE_IN == "%R2801"
        assert REG_CIP_APL_BARRIER_VOLTAGE_IN == "%R2801"
        assert REG_APL_BARRIER_VOLTAGE_OUT_MV == "%R2802"
        assert REG_APL_BARRIER_VOLTAGE_OUT == "%R2802"
        assert REG_CIP_APL_BARRIER_VOLTAGE_OUT == "%R2802"
        assert REG_APL_BARRIER_CURRENT_MA == "%R2803"
        assert REG_APL_BARRIER_CURRENT == "%R2803"
        assert REG_CIP_APL_BARRIER_CURRENT == "%R2803"
        assert REG_APL_BARRIER_IMPEDANCE_MOHM == "%R2804"
        assert REG_APL_BARRIER_IMPEDANCE == "%R2804"
        assert REG_CIP_APL_BARRIER_IMPEDANCE == "%R2804"
        assert REG_APL_BARRIER_TEMP_DEGC == "%R2805"
        assert REG_APL_BARRIER_TEMP == "%R2805"
        assert REG_CIP_APL_BARRIER_TEMP == "%R2805"
        assert REG_APL_BARRIER_POWER_MW == "%R2806"
        assert REG_APL_BARRIER_POWER == "%R2806"
        assert REG_CIP_APL_BARRIER_POWER == "%R2806"
        assert REG_APL_BARRIER_DIAGNOSTIC_CODE == "%R2807"
        assert REG_APL_BARRIER_DIAG_CODE == "%R2807"
        assert REG_BARRIER_DIAGNOSTIC_CODE == "%R2807"

        assert COIL_APL_BARRIER_ONLINE == "%M653"
        assert COIL_BARRIER_ONLINE == "%M653"
        assert COIL_CIP_APL_BARRIER_HEALTHY == "%M653"
        assert COIL_APL_BARRIER_HEALTHY == "%M653"
        assert COIL_CIP_APL_BARRIER_ACTIVE == "%M653"
        assert COIL_APL_BARRIER_ACTIVE == "%M653"
        assert COIL_APL_BARRIER_SAFETY_TRIP == "%M654"
        assert COIL_BARRIER_SAFETY_TRIP == "%M654"
        assert COIL_CIP_APL_BARRIER_TRIP == "%M654"
        assert COIL_APL_BARRIER_TRIP == "%M654"
        assert COIL_CIP_APL_BARRIER_FAULT == "%M654"
        assert COIL_APL_BARRIER_FAULT == "%M654"

    def test_protocol_constants(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_APL_BARRIER_CLASS_ID == 0x49
        assert CIP_APL_BARRIER_CLASS_ID == 0x49
        assert DEFAULT_SESSION_ID == 0x4150
        assert DEFAULT_SAFETY_EPID == "HORNER-OCS-APL-IS-BARRIER-SIL3"
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0x0000
        assert DEFAULT_BARRIER_IMPEDANCE_MOHM == 350
        assert DEFAULT_SHIELD_LEAKAGE_THRESHOLD_UA == 50.0
        assert DEFAULT_THERMAL_LIMIT_DEGC == 85.0
        assert LIMIT_2WISE_VOLTAGE_MAX_MV == 15000
        assert LIMIT_2WISE_CURRENT_MAX_MA == 215

    def test_barrier_operating_state_enum(self) -> None:
        assert BarrierOperatingState.DE_ENERGIZED == 0
        assert BarrierOperatingState.MONITORING == 1
        assert BarrierOperatingState.NORMAL_OPERATION == 2
        assert BarrierOperatingState.WARNING == 3
        assert BarrierOperatingState.FAULT_LOCKOUT == 4
        assert BarrierOperatingState.SAFETY_TRIP == 5

        # Aliases
        assert BarrierOperatingState.NORMAL == 2
        assert BarrierOperatingState.LOCKOUT == 4
        assert BarrierOperatingState.TRIP == 5
        assert BarrierOperatingState.TRIPPED == 5

    def test_barrier_profile_enum_and_specs(self) -> None:
        assert BarrierProfile.PROFILE_2WISE_15V_215MA == 0
        assert BarrierProfile.PROFILE_APL_TRUNK_50V_1500MA == 1
        assert BarrierProfile.PROFILE_SPUR_FIELD_15V_100MA == 2

        p_2wise = BarrierProfile.PROFILE_2WISE_15V_215MA
        assert p_2wise.v_max_out_mv == 15000
        assert p_2wise.i_max_ma == 215
        assert p_2wise.p_max_mw == 3225

        p_trunk = BarrierProfile.PROFILE_APL_TRUNK_50V_1500MA
        assert p_trunk.v_max_out_mv == 50000
        assert p_trunk.i_max_ma == 1500

        p_spur = BarrierProfile.PROFILE_SPUR_FIELD_15V_100MA
        assert p_spur.v_max_out_mv == 15000
        assert p_spur.i_max_ma == 100

    def test_diagnostic_code_values_and_safe_signed_comparisons(self) -> None:
        assert DiagnosticCode.DIAG_OK == 0x0000
        assert DiagnosticCode.DIAG_ERR_OVERVOLTAGE_BARRIER == 0xEEA1
        assert DiagnosticCode.DIAG_ERR_OVERCURRENT_EXCURSION == 0xEEA2
        assert DiagnosticCode.DIAG_ERR_THERMAL_BARRIER_OVERHEAT == 0xEEA3
        assert DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT == 0xEEA4
        assert DiagnosticCode.DIAG_ERR_LEAKAGE_TO_SHIELD_FAULT == 0xEEA5

        # Signed 16-bit equality test
        signed_overvoltage = 0xEEA1 - 0x10000
        assert DiagnosticCode.DIAG_ERR_OVERVOLTAGE_BARRIER == signed_overvoltage
        assert signed_overvoltage == DiagnosticCode.DIAG_ERR_OVERVOLTAGE_BARRIER
        assert DiagnosticCode.DIAG_ERR_OVERVOLTAGE_BARRIER != 0xEEA2
        assert (DiagnosticCode.DIAG_ERR_OVERVOLTAGE_BARRIER & 0xFFFF) == 0xEEA1
        assert (0xEEA1 & DiagnosticCode.DIAG_ERR_OVERVOLTAGE_BARRIER) == 0xEEA1
        assert hash(DiagnosticCode.DIAG_ERR_OVERVOLTAGE_BARRIER) == hash(0xEEA1)

        # Repr and Str
        assert "0xEEA1" in str(DiagnosticCode.DIAG_ERR_OVERVOLTAGE_BARRIER)
        assert "DIAG_ERR_OVERVOLTAGE_BARRIER" in repr(DiagnosticCode.DIAG_ERR_OVERVOLTAGE_BARRIER)

    def test_diagnostic_code_safe_signed_comparisons_all_codes(self) -> None:
        """Validate all DiagnosticCode values support safe signed/unsigned 16-bit comparisons."""
        for code, expected_u16 in [
            (DiagnosticCode.DIAG_OK, 0x0000),
            (DiagnosticCode.DIAG_ERR_OVERVOLTAGE_BARRIER, 0xEEA1),
            (DiagnosticCode.DIAG_ERR_OVERCURRENT_EXCURSION, 0xEEA2),
            (DiagnosticCode.DIAG_ERR_THERMAL_BARRIER_OVERHEAT, 0xEEA3),
            (DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT, 0xEEA4),
            (DiagnosticCode.DIAG_ERR_LEAKAGE_TO_SHIELD_FAULT, 0xEEA5),
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

        assert DiagnosticCode.DIAG_ERR_OVERVOLTAGE_BARRIER != DiagnosticCode.DIAG_OK
        assert DiagnosticCode.DIAG_ERR_OVERVOLTAGE_BARRIER != 0

    def test_barrier_profile_specs_table_integrity(self) -> None:
        """Validate BARRIER_PROFILE_SPECS dictionary configuration integrity."""
        assert len(BARRIER_PROFILE_SPECS) == 3
        for profile in BarrierProfile:
            assert profile in BARRIER_PROFILE_SPECS
            specs = BARRIER_PROFILE_SPECS[profile]
            assert "v_nominal_in_mv" in specs
            assert "v_nominal_out_mv" in specs
            assert "v_max_out_mv" in specs
            assert "i_nominal_ma" in specs
            assert "i_max_ma" in specs
            assert "p_max_mw" in specs
            assert "z_nominal_mohm" in specs
            assert "description" in specs

    def test_exceptions_hierarchy(self) -> None:
        """Validate CIPAPLBarrierSafetyError exception inheritance structure."""
        assert issubclass(BarrierOvervoltageFaultError, CIPAPLBarrierSafetyError)
        assert issubclass(BarrierOvercurrentFaultError, CIPAPLBarrierSafetyError)
        assert issubclass(BarrierThermalOverheatFaultError, CIPAPLBarrierSafetyError)
        assert issubclass(BarrierDualCrcSafetyFaultError, CIPAPLBarrierSafetyError)
        assert issubclass(BarrierShieldLeakageFaultError, CIPAPLBarrierSafetyError)

        assert BarrierOvervoltageError is BarrierOvervoltageFaultError
        assert BarrierOvercurrentError is BarrierOvercurrentFaultError
        assert BarrierThermalError is BarrierThermalOverheatFaultError
        assert BarrierCrcFaultError is BarrierDualCrcSafetyFaultError
        assert BarrierLeakageError is BarrierShieldLeakageFaultError

    def test_barrier_status_bits(self) -> None:
        assert BarrierStatusBits.ONLINE == 1
        assert BarrierStatusBits.NORMAL == 2
        assert BarrierStatusBits.OVERVOLTAGE == 4
        assert BarrierStatusBits.OVERCURRENT == 8
        assert BarrierStatusBits.THERMAL_OVERHEAT == 16
        assert BarrierStatusBits.CRC_FAULT == 32
        assert BarrierStatusBits.LEAKAGE_FAULT == 64
        assert BarrierStatusBits.SAFETY_TRIPPED == 128


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
        data = bytearray(b"CIP_SAFETY_APL_BARRIER_PAYLOAD_TEST")
        crc1 = compute_crc_s1(bytes(data))
        data[0] ^= 0x01
        crc2 = compute_crc_s1(bytes(data))
        assert crc1 != crc2

    def test_crc_s2_single_bit_perturbation(self) -> None:
        data = bytearray(b"INVERTED_HEADER_TEST_BYTES_FOR_CRC_S2")
        crc1 = compute_crc_s2(bytes(data))
        data[2] ^= 0x80
        crc2 = compute_crc_s2(bytes(data))
        assert crc1 != crc2

    def test_verify_dual_crc_s_helper(self) -> None:
        payload = b"\xAA\xBB\xCC\xDD"
        inv_hdr = b"\x11\x22\x33\x44\x55\x66"
        c1 = compute_crc_s1(payload)
        c2 = compute_crc_s2(inv_hdr)
        assert verify_dual_crc_s(payload, inv_hdr, c1, c2) is True
        assert verify_dual_crc_s(payload, inv_hdr, c1 ^ 0x01, c2) is False
        assert verify_dual_crc_s(payload, inv_hdr, c1, c2 ^ 0x01) is False

    def test_epid_hash_and_crc32(self) -> None:
        epid = "HORNER-OCS-APL-IS-BARRIER-SIL3"
        h = compute_epid_hash(epid)
        assert 0 <= h <= 0xFFFF
        crc32_val = compute_epid_crc32(epid)
        assert crc32_val == 0x09AAE062

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
            + (0).to_bytes(1, "big")
            + (24000).to_bytes(2, "big")
            + (14500).to_bytes(2, "big")
            + (150).to_bytes(2, "big")
            + (35).to_bytes(2, "big")
            + (350).to_bytes(2, "big")
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
    """Validate CIPAPLBarrierPacket dataclass, packing, unpacking, and verification."""

    def test_packet_creation_and_crc_computation(self) -> None:
        pkt = CIPAPLBarrierPacket(
            session_id=DEFAULT_SESSION_ID,
            sequence_number=10,
            timestamp_us=500,
            barrier_state=BarrierOperatingState.NORMAL_OPERATION,
            profile=BarrierProfile.PROFILE_2WISE_15V_215MA,
            voltage_in_mv=24000,
            voltage_out_mv=14500,
            current_ma=150,
            temp_degc=35,
        )
        assert pkt.crc_s1 != 0
        assert pkt.crc_s2 != 0
        assert pkt.validate_crcs() is True
        assert pkt.is_valid() is True

    def test_packet_property_getters_and_setters(self) -> None:
        pkt = CIPAPLBarrierPacket()
        assert pkt.sequence == 0
        pkt.sequence = 42
        assert pkt.sequence == 42
        assert pkt.sequence_number == 42

        assert pkt.timestamp == 0
        pkt.timestamp = 9999
        assert pkt.timestamp_us == 9999

        assert pkt.voltage_in == 24000
        assert pkt.voltage_out == 14500
        assert pkt.current == 150
        assert pkt.temperature == 35
        assert pkt.impedance == DEFAULT_BARRIER_IMPEDANCE_MOHM
        assert pkt.power_mw == int(14500 * 150 / 1000)

    def test_pack_and_unpack_roundtrip(self) -> None:
        pkt = create_valid_apl_barrier_packet(
            sequence=7,
            timestamp_us=12345,
            barrier_state=BarrierOperatingState.NORMAL_OPERATION,
            profile=BarrierProfile.PROFILE_2WISE_15V_215MA,
            voltage_in_mv=24000,
            voltage_out_mv=14200,
            current_ma=180,
            temp_degc=40,
            payload_bytes=b"\xDE\xAD\xBE\xEF\xCA\xFE",
        )
        raw = pkt.pack()
        unpacked = CIPAPLBarrierPacket.unpack(raw)

        assert unpacked.session_id == pkt.session_id
        assert unpacked.sequence_number == 7
        assert unpacked.timestamp_us == 12345
        assert unpacked.barrier_state == BarrierOperatingState.NORMAL_OPERATION
        assert unpacked.profile == BarrierProfile.PROFILE_2WISE_15V_215MA
        assert unpacked.voltage_in_mv == 24000
        assert unpacked.voltage_out_mv == 14200
        assert unpacked.current_ma == 180
        assert unpacked.temp_degc == 40
        assert unpacked.payload_bytes == b"\xDE\xAD\xBE\xEF\xCA\xFE"
        assert unpacked.validate_crcs() is True

    def test_unpack_too_short_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            CIPAPLBarrierPacket.unpack(b"\x01\x02\x03")

    def test_tampered_payload_fails_validation(self) -> None:
        pkt = create_valid_apl_barrier_packet()
        assert pkt.validate_crcs() is True
        pkt.payload_bytes = b"\xFF\xFF\xFF\xFF"
        assert pkt.validate_crcs() is False


# ============================================================================
# 4. TestBarrierProfilesAndPowerCalculation
# ============================================================================

class TestBarrierProfilesAndPowerCalculation:
    """Validate 3 barrier profiles and electrical power calculations."""

    def test_profile_2wise_parameters(self) -> None:
        engine = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA)
        assert engine.v_max_out_mv == 15000
        assert engine.i_max_ma == 215
        assert engine.nominal_voltage_out_mv == 14500
        assert engine.nominal_current_ma == 150

    def test_profile_trunk_parameters(self) -> None:
        engine = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_APL_TRUNK_50V_1500MA)
        assert engine.v_max_out_mv == 50000
        assert engine.i_max_ma == 1500

    def test_profile_spur_parameters(self) -> None:
        engine = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_SPUR_FIELD_15V_100MA)
        assert engine.v_max_out_mv == 15000
        assert engine.i_max_ma == 100

    def test_power_calculation_formula(self) -> None:
        engine = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA)
        engine.voltage_out_mv = 14000
        engine.current_ma = 200
        # P = 14000 * 200 / 1000 = 2800 mW
        assert engine.power_mw == 2800


# ============================================================================
# 5. TestOvervoltageInjectionAndTrip
# ============================================================================

class TestOvervoltageInjectionAndTrip:
    """Validate overvoltage fault injection, safety trip, and recovery."""

    def test_inject_overvoltage_default_trips_0xEEA1(self) -> None:
        engine = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA)
        engine.connect()
        assert engine.online is True

        engine.inject_overvoltage()
        assert engine.barrier_state == BarrierOperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_OVERVOLTAGE_BARRIER
        assert engine.fault_code == 0xEEA1
        assert engine.online is False
        assert engine.tripped is True

    def test_inject_overvoltage_custom_voltage(self) -> None:
        engine = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA)
        engine.connect()
        engine.inject_overvoltage(16000)
        assert engine.voltage_out_mv == 16000
        assert engine.diagnostic_code == DIAG_ERR_OVERVOLTAGE_BARRIER

    def test_receive_packet_with_overvoltage_trips(self) -> None:
        engine = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA)
        engine.connect()
        pkt = create_valid_apl_barrier_packet(voltage_out_mv=16500)
        assert engine.receive_packet(pkt) is False
        assert engine.diagnostic_code == DIAG_ERR_OVERVOLTAGE_BARRIER
        assert engine.tripped is True

    def test_overvoltage_recovery(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        engine.inject_overvoltage(17000)
        assert engine.tripped is True
        engine.clear_fault()
        assert engine.barrier_state == BarrierOperatingState.NORMAL_OPERATION
        assert engine.diagnostic_code == DIAG_OK
        assert engine.fault_code == 0
        assert engine.online is True
        assert engine.tripped is False


# ============================================================================
# 6. TestOvercurrentExcursionAndTrip
# ============================================================================

class TestOvercurrentExcursionAndTrip:
    """Validate overcurrent excursion fault injection, safety trip, and recovery."""

    def test_inject_overcurrent_default_trips_0xEEA2(self) -> None:
        engine = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA)
        engine.connect()
        assert engine.online is True

        engine.inject_overcurrent()
        assert engine.barrier_state == BarrierOperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_OVERCURRENT_EXCURSION
        assert engine.fault_code == 0xEEA2
        assert engine.online is False
        assert engine.tripped is True

    def test_inject_overcurrent_custom_current(self) -> None:
        engine = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA)
        engine.connect()
        engine.inject_overcurrent(250)
        assert engine.current_ma == 250
        assert engine.diagnostic_code == DIAG_ERR_OVERCURRENT_EXCURSION

    def test_receive_packet_with_overcurrent_trips(self) -> None:
        engine = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA)
        engine.connect()
        pkt = create_valid_apl_barrier_packet(current_ma=300)
        assert engine.receive_packet(pkt) is False
        assert engine.diagnostic_code == DIAG_ERR_OVERCURRENT_EXCURSION
        assert engine.tripped is True

    def test_overcurrent_recovery(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        engine.inject_overcurrent(280)
        assert engine.tripped is True
        engine.clear_fault()
        assert engine.online is True
        assert engine.tripped is False


# ============================================================================
# 7. TestThermalBarrierOverheatAndTrip
# ============================================================================

class TestThermalBarrierOverheatAndTrip:
    """Validate thermal overheat surveillance and fault trip (> 85.0 degC)."""

    def test_inject_thermal_fault_default_trips_0xEEA3(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        assert engine.online is True

        engine.inject_thermal_fault()
        assert engine.barrier_state == BarrierOperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_THERMAL_BARRIER_OVERHEAT
        assert engine.fault_code == 0xEEA3
        assert engine.temp_degc > 85
        assert engine.online is False
        assert engine.tripped is True

    def test_inject_thermal_fault_custom_temperature(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        engine.inject_thermal_fault(95)
        assert engine.temp_degc == 95
        assert engine.diagnostic_code == DIAG_ERR_THERMAL_BARRIER_OVERHEAT

    def test_receive_packet_with_overheat_trips(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        pkt = create_valid_apl_barrier_packet(temp_degc=89)
        assert engine.receive_packet(pkt) is False
        assert engine.diagnostic_code == DIAG_ERR_THERMAL_BARRIER_OVERHEAT
        assert engine.tripped is True

    def test_thermal_overheat_recovery(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        engine.inject_thermal_fault(90)
        assert engine.tripped is True
        engine.clear_fault()
        assert engine.online is True
        assert engine.tripped is False


# ============================================================================
# 8. TestShieldLeakageFaultAndTrip
# ============================================================================

class TestShieldLeakageFaultAndTrip:
    """Validate shield leakage current surveillance and fault trip (> 50 uA)."""

    def test_inject_leakage_fault_default_trips_0xEEA5(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        assert engine.online is True

        engine.inject_leakage_fault()
        assert engine.barrier_state == BarrierOperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_LEAKAGE_TO_SHIELD_FAULT
        assert engine.fault_code == 0xEEA5
        assert engine.leakage_ua > 50.0
        assert engine.online is False
        assert engine.tripped is True

    def test_inject_leakage_fault_custom_value(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        engine.inject_leakage_fault(80.5)
        assert engine.leakage_ua == 80.5
        assert engine.diagnostic_code == DIAG_ERR_LEAKAGE_TO_SHIELD_FAULT

    def test_shield_leakage_recovery(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        engine.inject_leakage_fault(65.0)
        assert engine.tripped is True
        engine.clear_fault()
        assert engine.online is True
        assert engine.tripped is False


# ============================================================================
# 9. TestCrcCorruptionInjectionAndTrip
# ============================================================================

class TestCrcCorruptionInjectionAndTrip:
    """Validate Dual CRC safety checksum corruption detection and counter."""

    def test_inject_crc_fault_trips_0xEEA4(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        assert engine.packet_loss_counter == 0

        engine.inject_crc_fault()
        assert engine.barrier_state == BarrierOperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.fault_code == 0xEEA4
        assert engine.packet_loss_counter == 1
        assert engine.online is False
        assert engine.tripped is True

    def test_receive_packet_with_corrupted_crc_s1_trips_0xEEA4(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        bad_pkt = create_valid_apl_barrier_packet()
        bad_pkt.crc_s1 = 0xDEAD
        assert engine.receive_packet(bad_pkt) is False
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.packet_loss_counter == 1

    def test_receive_packet_with_corrupted_crc_s2_trips_0xEEA4(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        bad_pkt = create_valid_apl_barrier_packet()
        bad_pkt.crc_s2 = 0xBEEF
        assert engine.receive_packet(bad_pkt) is False
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.packet_loss_counter == 1

    def test_packet_loss_counter_monotonic_increment(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        assert engine.packet_loss_counter == 0
        engine.inject_crc_fault()
        assert engine.packet_loss_counter == 1
        engine.inject_crc_fault()
        assert engine.packet_loss_counter == 2


# ============================================================================
# 10. TestSafeStopInterlockAndCoils
# ============================================================================

class TestSafeStopInterlockAndCoils:
    """Validate discrete coils %M653 (ONLINE) and %M654 (SAFETY_TRIP) interlock."""

    def test_healthy_coils_state(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_BARRIER_ONLINE) is True
        assert rt.read_bit(COIL_CIP_APL_BARRIER_SAFETY_TRIP) is False

    def test_safe_stop_interlock_on_all_diagnostic_faults(self) -> None:
        rt = RegisterTable()
        fault_injections = [
            lambda eng: eng.inject_overvoltage(16000),
            lambda eng: eng.inject_overcurrent(250),
            lambda eng: eng.inject_thermal_fault(90),
            lambda eng: eng.inject_leakage_fault(60.0),
            lambda eng: eng.inject_crc_fault(),
        ]
        for inj in fault_injections:
            engine = CIPAPLBarrierSafetyEngine()
            engine.connect()
            inj(engine)
            engine.sync_to_registers(rt)
            assert rt.read_bit(COIL_CIP_APL_BARRIER_ONLINE) is False
            assert rt.read_bit(COIL_CIP_APL_BARRIER_SAFETY_TRIP) is True

    def test_coil_mutual_exclusivity(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        # Healthy
        b_on = rt.read_bit(COIL_CIP_APL_BARRIER_ONLINE)
        b_trip = rt.read_bit(COIL_CIP_APL_BARRIER_SAFETY_TRIP)
        assert b_on != b_trip

        # Tripped
        engine.inject_overvoltage(16000)
        engine.sync_to_registers(rt)
        b_on = rt.read_bit(COIL_CIP_APL_BARRIER_ONLINE)
        b_trip = rt.read_bit(COIL_CIP_APL_BARRIER_SAFETY_TRIP)
        assert b_on != b_trip

    def test_clear_fault_restores_healthy_coils(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        rt = RegisterTable()
        engine.inject_overvoltage(16000)
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_BARRIER_ONLINE) is False
        assert rt.read_bit(COIL_CIP_APL_BARRIER_SAFETY_TRIP) is True

        engine.clear_fault()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_APL_BARRIER_ONLINE) is True
        assert rt.read_bit(COIL_CIP_APL_BARRIER_SAFETY_TRIP) is False

    def test_reset_restores_nominal_state(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        engine.inject_thermal_fault(95)
        assert engine.tripped is True
        engine.reset()
        assert engine.barrier_state == BarrierOperatingState.NORMAL_OPERATION
        assert engine.diagnostic_code == DIAG_OK
        assert engine.sequence_number == 0
        assert engine.tx_frame_count == 0
        assert engine.rx_frame_count == 0
        assert engine.packet_loss_counter == 0
        assert engine.online is True

    def test_connect_and_disconnect_coil_behavior(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.disconnect()
        assert engine.barrier_state == BarrierOperatingState.DE_ENERGIZED
        assert engine.online is False
        engine.connect()
        assert engine.barrier_state == BarrierOperatingState.NORMAL_OPERATION
        assert engine.online is True

    def test_trip_safety_and_trip_fault_aliases(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        engine.trip_fault(DIAG_ERR_OVERVOLTAGE_BARRIER, "Test trip")
        assert engine.barrier_state == BarrierOperatingState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_OVERVOLTAGE_BARRIER
        assert engine.fault_code == 0xEEA1

    def test_status_word_bitmask_flags(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        assert (engine.status_word & BarrierStatusBits.ONLINE) != 0
        assert (engine.status_word & BarrierStatusBits.NORMAL) != 0
        assert (engine.status_word & BarrierStatusBits.SAFETY_TRIPPED) == 0

        engine.inject_overvoltage(16000)
        assert (engine.status_word & BarrierStatusBits.OVERVOLTAGE) != 0
        assert (engine.status_word & BarrierStatusBits.SAFETY_TRIPPED) != 0
        assert (engine.status_word & BarrierStatusBits.ONLINE) == 0

    def test_packet_creation_helper_aliases(self) -> None:
        p1 = create_valid_apl_barrier_packet()
        p2 = create_valid_barrier_packet()
        p3 = create_valid_cip_barrier_packet()
        assert p1.validate_crcs() is True
        assert p2.validate_crcs() is True
        assert p3.validate_crcs() is True

    def test_engine_aliases(self) -> None:
        e1 = CipSafetyAplBarrierEngine()
        e2 = CIPAPLBarrierEngine()
        e3 = APLBarrierSafetyEngine()
        e4 = APLBarrierEngine()
        e5 = BarrierSafetyEngine()
        assert isinstance(e1, CIPAPLBarrierSafetyEngine)
        assert isinstance(e2, CIPAPLBarrierSafetyEngine)
        assert isinstance(e3, CIPAPLBarrierSafetyEngine)
        assert isinstance(e4, CIPAPLBarrierSafetyEngine)
        assert isinstance(e5, CIPAPLBarrierSafetyEngine)


# ============================================================================
# 11. TestHornerRegisterTableSynchronization
# ============================================================================

class TestHornerRegisterTableSynchronization:
    """Validate bit-exact Horner OCS register synchronization (%R2800..%R2807)."""

    def test_sync_to_registers_healthy(self) -> None:
        rt = RegisterTable()
        engine = CIPAPLBarrierSafetyEngine(profile=BarrierProfile.PROFILE_2WISE_15V_215MA)
        engine.connect()
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_CIP_APL_BARRIER_STATUS) == int(BarrierOperatingState.NORMAL_OPERATION)
        assert (rt.read_word(REG_CIP_APL_BARRIER_VOLTAGE_IN_MV) & 0xFFFF) == 24000
        assert (rt.read_word(REG_CIP_APL_BARRIER_VOLTAGE_OUT_MV) & 0xFFFF) == 14500
        assert (rt.read_word(REG_CIP_APL_BARRIER_CURRENT_MA) & 0xFFFF) == 150
        assert (rt.read_word(REG_CIP_APL_BARRIER_IMPEDANCE_MOHM) & 0xFFFF) == 350
        assert rt.read_word(REG_CIP_APL_BARRIER_TEMP_DEGC) == 35
        assert (rt.read_word(REG_CIP_APL_BARRIER_POWER_MW) & 0xFFFF) == 2175
        assert (rt.read_word(REG_CIP_APL_BARRIER_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
        assert rt.read_bit(COIL_CIP_APL_BARRIER_ONLINE) is True
        assert rt.read_bit(COIL_CIP_APL_BARRIER_SAFETY_TRIP) is False

    def test_sync_to_registers_tripped(self) -> None:
        rt = RegisterTable()
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        engine.inject_overvoltage(16200)
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_CIP_APL_BARRIER_STATUS) == int(BarrierOperatingState.SAFETY_TRIP)
        assert (rt.read_word(REG_CIP_APL_BARRIER_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEEA1
        assert (rt.read_word(REG_CIP_APL_BARRIER_VOLTAGE_OUT_MV) & 0xFFFF) == 16200
        assert rt.read_bit(COIL_CIP_APL_BARRIER_ONLINE) is False
        assert rt.read_bit(COIL_CIP_APL_BARRIER_SAFETY_TRIP) is True

    def test_signed_16bit_safe_masking(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, REG_CIP_APL_BARRIER_DIAGNOSTIC_CODE, 0xEEA1)
        w = rt.read_word(REG_CIP_APL_BARRIER_DIAGNOSTIC_CODE)
        assert (w & 0xFFFF) == 0xEEA1

    def test_privilege_modes_user_and_system(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R2800", 2, privilege=PrivilegeMode.USER)
        assert rt.read_word("%R2800") == 2
        safe_write_word(rt, "%R2800", 5, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_word("%R2800") == 5


# ============================================================================
# 12. TestPureIEC61131StructuredTextAndSecurity
# ============================================================================

class TestPureIEC61131StructuredTextAndSecurity:
    """Validate pure ST POU CipSafetyAplBarrierSync and anti-ladder security guard."""

    def test_st_program_constant_and_aliases(self) -> None:
        assert "PROGRAM CipSafetyAplBarrierSync" in ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC
        assert CIP_SAFETY_APL_BARRIER_SYNC_POU == ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC
        assert CIP_SAFETY_APL_BARRIER_PURE_ST_POU == ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC
        assert CIP_SAFETY_APL_BARRIER_POU == ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC

    def test_st_parser_validates_pou(self) -> None:
        res = STParser.validate_code(ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC)
        assert res.status == AgentStatus.SUCCESS

    def test_st_parser_ast_bound_registers(self) -> None:
        ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC)
        expected = {
            "%R2800", "%R2801", "%R2802", "%R2803",
            "%R2804", "%R2805", "%R2806", "%R2807",
            "%M653", "%M654",
        }
        assert expected.issubset(set(ast.bound_registers))

    def test_security_guard_assert_pure_st_content(self) -> None:
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_APL_BARRIER_SYNC)

    def test_verify_pure_st_helper_functions(self) -> None:
        assert verify_cip_safety_apl_barrier_pure_st() is True
        assert verify_barrier_pure_st() is True

    @pytest.mark.parametrize(
        "construct",
        [
            "---[ ]---",
            "---[/]---",
            "---( )---",
            "---(/)---",
            "RUNG 1: LD %R2800",
            "NETWORK 10:",
            "XIC %M653",
            "XIO %M654",
            "OTE %M653",
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
        engine = CIPAPLBarrierSafetyEngine()
        assert isinstance(engine, ILogicUnit)

    def test_scan_step_various_argument_types(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        # dt float
        res1 = engine.scan_step(0.0004)
        assert res1.status == AgentStatus.SUCCESS

        # ScanContext
        ctx = ScanContext(cycle=1, dt=0.0004)
        res2 = engine.scan_step(ctx)
        assert res2.status == AgentStatus.SUCCESS

        # kwargs context
        res3 = engine.scan_step(context=ctx)
        assert res3.status == AgentStatus.SUCCESS

    def test_step_and_execute_aliases(self) -> None:
        engine = CIPAPLBarrierSafetyEngine()
        engine.connect()
        res1 = engine.step(0.0004)
        assert res1.status == AgentStatus.SUCCESS
        res2 = engine.execute()
        assert res2.status == AgentStatus.SUCCESS

    def test_100_cycle_simulation_soak_memory_bounded(self) -> None:
        rt = RegisterTable()
        engine = CIPAPLBarrierSafetyEngine(register_table=rt)
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


# ============================================================================
# 14. TestVerificationRunner9StagesAndCli
# ============================================================================

class TestVerificationRunner9StagesAndCli:
    """Validate 9-stage verification suite, 4-state engineering contract, and CLI."""

    def test_runner_passes_all_9_stages(self) -> None:
        res = run_cip_safety_apl_barrier_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["total_stages"] == 9
        assert res["stages_passed"] == 9

    def test_runner_evidence_data_integrity(self) -> None:
        res = run_cip_safety_apl_barrier_verification()
        assert "data" in res
        assert res["data"]["work_package"] == "W319"
        assert res["data"]["gate"] == "G8"
        assert len(res["data"]["stages"]) == 9
        for stage in res["data"]["stages"]:
            assert stage["passed"] is True
            assert "timing_ms" in stage

    def test_runner_no_file_written_when_output_path_is_none(self) -> None:
        res = run_cip_safety_apl_barrier_verification(output_path=None)
        assert res["status"] == "success"

    def test_runner_writes_file_when_output_path_specified(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = tf.name
        try:
            res = run_cip_safety_apl_barrier_verification(output_path=temp_path)
            assert res["status"] == "success"
            assert Path(temp_path).exists()
            with open(temp_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["work_package"] == "W319"
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_quick_mode_verification(self) -> None:
        res = run_cip_safety_apl_barrier_verification(quick=True)
        assert res["status"] == "success"

    def test_module_cli_direct_execution(self) -> None:
        """Verify executing module CLI directly with tempfile output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "module_barrier_evidence.json"
            cmd = [
                sys.executable,
                "-m",
                "jev_cscape.telemetry.cip_safety_apl_barrier",
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
        script_path = REPO_ROOT / "scripts" / "run_cip_safety_apl_barrier_verification.py"
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
            assert loaded["work_package"] == "W319"
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_script_cli_json_mode(self) -> None:
        script_path = REPO_ROOT / "scripts" / "run_cip_safety_apl_barrier_verification.py"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "test_barrier_json_evidence.json"
            cmd = [sys.executable, str(script_path), "--json", "--quick", "--output", str(tmp_out)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            assert proc.returncode == 0
            data = json.loads(proc.stdout)
            assert data["status"] == "success"
            assert data["stages_passed"] == 9
            assert tmp_out.exists()

    def test_script_runner_interop_cli(self) -> None:
        """Verify interop with scripts/run_cip_safety_apl_barrier_verification.py CLI."""
        scripts_runner_path = REPO_ROOT / "scripts" / "run_cip_safety_apl_barrier_verification.py"
        assert scripts_runner_path.exists()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "test_barrier_script_evidence.json"
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


