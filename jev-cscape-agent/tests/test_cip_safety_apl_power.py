"""Comprehensive Unit Test Suite for Wave W295 CIP Safety Over Ethernet-APL Intrinsically Safe Power Coordination.

Work Package: W295 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Ethernet-APL Power Delivery & 2-WISE Intrinsically Safe Coordination (IEC 60079-47 / IEEE 802.3cg).

Covers Comprehensive Deterministic Unit Tests across 14 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnosticCodes: Protocol constants, register mappings (%R2560..%R2567),
   discrete coils (%M597..%M598), extended register aliases, diagnostic codes (0x0000, 0xEE21..0xEE28),
   signed/unsigned 16-bit representations, bitwise behavior, PowerClass and PowerOperationalState enums,
   CipSafetyAplPowerStatusBits, and protocol exceptions hierarchy.
2. TestDualSafetyCrcCalculation: CRC-S1 (polynomial 0x5935) and CRC-S2 (polynomial 0x755B inverted header)
   calculation, determinism, 16-bit bounds, single-bit flip sensitivity, header field tampering detection,
   seed variations, compute_crc aliases, and parameter validation.
3. TestCipSafetyAplPowerFrameModel: CipSafetyAplPowerFrame model defaults, CRC generation and verification,
   payload corruption mutation, CRC-S1 / CRC-S2 mutation, binary serialization and deserialization bit-exact round-trip,
   and truncated payload error handling.
4. TestInrushCurrentLimiting: Inrush current monitoring (< 1.25x steady state nominal), inrush limit exceedance
   trip (0xEE27), status word INRUSH_ACTIVE flag, safe output de-energization, and clean recovery.
5. TestUnderVoltageAndOverCurrentTrips: Bus under-voltage trip (Vbus < 9000 mV, 0xEE21), status bit assertion,
   bus over-current trip (Ibus > 1500 mA, 0xEE22), safe state de-energization in < 5.0 ms, and fault recovery.
6. TestGroundLeakageAndThermalOverloadTrips: Ground leakage current surveillance (> 10 mA, 0xEE23), safe output
   clamping to 0x00, switch thermal overload (> 85.0 C, 0xEE24), status word warning bit assertion, and recovery.
7. TestCrowbarTripAndFastDeenergization: Hardware crowbar circuit clamp to 0V upon fault, status bit CROWBAR_TRIPPED,
   diagnostic code 0xEE28, deterministic safe de-energization in < 5.0 ms, and power-off / power-on power cycling.
8. TestHornerOcsRegisterSynchronization: Bit-exact synchronization to Horner OCS analog registers (%R2560..%R2567)
   and discrete coils (%M597..%M598) across nominal and faulted states, bit-packing, privilege modes, and coil exclusivity.
9. TestPureIEC61131StructuredTextAndSecurity: Pure IEC 61131-3 Structured Text POU CipSafetyAplPowerSync syntax
   validation via STParser and SecurityGuard, variable address bindings, and strict rejection of ladder logic constructs
   (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
10. TestILogicUnitCompliance: ILogicUnit interface compliance (scan_step, step, execute, reset), ScanContext and
    RegisterTable propagation hierarchy, ExecutionResult contract validation, and unpowered initialization.
11. TestFrameTransmissionAndReception: Safety power frame construction, transmission sequence incrementation,
    reception validation, Safety Network Number (SNN) mismatch interception, CRC-S1 / CRC-S2 corruption interception,
    ingress threshold violation interception, and heartbeat watchdog reset.
12. TestSoakAndMemoryStability: 100-cycle continuous scan soak test with zero fault trips, 100% SUCCESS outcomes,
    monotonic counter increments, and stable memory footprint verified via tracemalloc.
13. TestNineStageVerificationRunner: Complete 9-stage verification suite run_cip_safety_apl_power_verification,
    strict 4-state engineering contract validation, stage timing metrics, and JSON evidence emission.
14. TestPowerClassesAndEdgeCases: PowerClass A (500mW spur) and PowerClass D (field switch spur) nominal metrics,
    consumed_mw getter and setter overrides, and trip_fail_safe with custom diagnostic codes.
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
from jev_cscape.telemetry.cip_safety_apl_power import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_APL_POWER_CLASS_ID,
    DEFAULT_SAFETY_NETWORK_NUMBER,
    DEFAULT_SNN,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    UNDER_VOLTAGE_THRESHOLD_MV,
    OVER_CURRENT_THRESHOLD_MA,
    GROUND_LEAKAGE_THRESHOLD_MA,
    THERMAL_OVERLOAD_THRESHOLD_C,
    MAX_INRUSH_RATIO,
    MAX_DEENERGIZE_TIME_MS,
    CLASS_A_NOMINAL_VOLTAGE_MV,
    CLASS_A_NOMINAL_CURRENT_MA,
    CLASS_A_MAX_POWER_MW,
    CLASS_C_NOMINAL_VOLTAGE_MV,
    CLASS_C_NOMINAL_CURRENT_MA,
    CLASS_C_MAX_CURRENT_MA,
    CLASS_C_MAX_POWER_MW,
    CLASS_D_NOMINAL_VOLTAGE_MV,
    CLASS_D_NOMINAL_CURRENT_MA,
    CLASS_D_MAX_CURRENT_MA,
    CLASS_D_MAX_POWER_MW,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CRC_INIT,
    REG_CIP_SAFETY_POWER_STATUS,
    REG_CIP_SAFETY_POWER_VOLTAGE_MV,
    REG_CIP_SAFETY_POWER_CURRENT_MA,
    REG_CIP_SAFETY_POWER_CONSUMED_MW,
    REG_CIP_SAFETY_POWER_SPUR_MASK,
    REG_CIP_SAFETY_POWER_DIAGNOSTIC_CODE,
    REG_CIP_SAFETY_POWER_STATUS_WORD,
    REG_CIP_SAFETY_POWER_SEQUENCE_COUNTER,
    COIL_CIP_SAFETY_POWER_HEALTHY,
    COIL_CIP_SAFETY_POWER_TRIP,
    REG_POWER_STATUS,
    REG_POWER_VOLTAGE_MV,
    REG_POWER_CURRENT_MA,
    REG_POWER_CONSUMED_MW,
    REG_POWER_SPUR_MASK,
    REG_POWER_DIAGNOSTIC_CODE,
    REG_POWER_STATUS_WORD,
    REG_POWER_SEQUENCE_COUNTER,
    REG_CIP_SAFETY_POWER_STATE,
    REG_CIP_SAFETY_POWER_BUS_VOLTAGE_MV,
    REG_CIP_SAFETY_POWER_BUS_CURRENT_MA,
    REG_CIP_SAFETY_POWER_BUS_POWER_MW,
    COIL_POWER_HEALTHY,
    COIL_POWER_TRIP,
    COIL_CIP_SAFETY_POWER_OPERATIONAL,
    COIL_CIP_SAFETY_POWER_ACTIVE,
    COIL_CIP_SAFETY_POWER_FAULT,
    COIL_CIP_SAFETY_POWER_ALARM,
    DiagnosticCode,
    DIAG_OK,
    DIAG_ERR_UNDER_VOLTAGE,
    DIAG_ERR_OVER_CURRENT,
    DIAG_ERR_GROUND_LEAKAGE,
    DIAG_ERR_THERMAL_OVERLOAD,
    DIAG_ERR_CRC_S1_FAULT,
    DIAG_ERR_CRC_S2_FAULT,
    DIAG_ERR_INRUSH_LIMIT_EXCEEDED,
    DIAG_ERR_FAIL_SAFE_TRIP,
    CipSafetyAplPowerDiagnosticCode,
    AplPowerDiagnosticCode,
    PowerClass,
    AplPowerClass,
    CipSafetyAplPowerClass,
    PowerOperationalState,
    CipSafetyAplPowerState,
    AplPowerOperationalState,
    PowerState,
    CipSafetyAplPowerStatusBits,
    PowerStatusBits,
    CipSafetyPowerStatusBits,
    CipSafetyAplPowerError,
    UnderVoltageError,
    OverCurrentError,
    GroundLeakageError,
    ThermalOverloadError,
    InrushLimitExceededError,
    CrcS1FaultError,
    CrcS2FaultError,
    CrowbarTrippedError,
    FailSafeTripError,
    calculate_crc_s1,
    calculate_crc_s2,
    compute_crc_s1,
    compute_crc_s2,
    CipSafetyAplPowerFrame,
    ST_PROGRAM_CIP_SAFETY_APL_POWER_SYNC,
    CIP_SAFETY_APL_POWER_PURE_ST_POU,
    CipSafetyAplPowerSync,
    verify_cip_safety_apl_power_pure_st,
    CipSafetyAplPowerEngine,
    run_cip_safety_apl_power_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnosticCodes
# ============================================================================

class TestConstantsEnumsAndDiagnosticCodes:
    """Validate ODVA CIP Safety Over Ethernet-APL Power Coordination constants, mappings, and enums."""

    def test_canonical_register_and_coil_mappings(self) -> None:
        """Verify exact canonical register addresses %R2560..%R2567 and coils %M597..%M598."""
        assert REG_CIP_SAFETY_POWER_STATUS == "%R2560"
        assert REG_CIP_SAFETY_POWER_VOLTAGE_MV == "%R2561"
        assert REG_CIP_SAFETY_POWER_CURRENT_MA == "%R2562"
        assert REG_CIP_SAFETY_POWER_CONSUMED_MW == "%R2563"
        assert REG_CIP_SAFETY_POWER_SPUR_MASK == "%R2564"
        assert REG_CIP_SAFETY_POWER_DIAGNOSTIC_CODE == "%R2565"
        assert REG_CIP_SAFETY_POWER_STATUS_WORD == "%R2566"
        assert REG_CIP_SAFETY_POWER_SEQUENCE_COUNTER == "%R2567"

        assert COIL_CIP_SAFETY_POWER_HEALTHY == "%M597"
        assert COIL_CIP_SAFETY_POWER_TRIP == "%M598"

    def test_extended_register_and_coil_aliases(self) -> None:
        """Verify compatibility aliases for all register and coil identifiers."""
        assert REG_POWER_STATUS == "%R2560"
        assert REG_POWER_VOLTAGE_MV == "%R2561"
        assert REG_POWER_CURRENT_MA == "%R2562"
        assert REG_POWER_CONSUMED_MW == "%R2563"
        assert REG_POWER_SPUR_MASK == "%R2564"
        assert REG_POWER_DIAGNOSTIC_CODE == "%R2565"
        assert REG_POWER_STATUS_WORD == "%R2566"
        assert REG_POWER_SEQUENCE_COUNTER == "%R2567"

        assert REG_CIP_SAFETY_POWER_STATE == "%R2560"
        assert REG_CIP_SAFETY_POWER_BUS_VOLTAGE_MV == "%R2561"
        assert REG_CIP_SAFETY_POWER_BUS_CURRENT_MA == "%R2562"
        assert REG_CIP_SAFETY_POWER_BUS_POWER_MW == "%R2563"

        assert COIL_POWER_HEALTHY == "%M597"
        assert COIL_POWER_TRIP == "%M598"
        assert COIL_CIP_SAFETY_POWER_OPERATIONAL == "%M597"
        assert COIL_CIP_SAFETY_POWER_ACTIVE == "%M597"
        assert COIL_CIP_SAFETY_POWER_FAULT == "%M598"
        assert COIL_CIP_SAFETY_POWER_ALARM == "%M598"

    def test_protocol_constants_and_power_thresholds(self) -> None:
        """Verify protocol class IDs, SNN, watchdog timeout, and safety thresholds."""
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_APL_POWER_CLASS_ID == 0x40

        assert DEFAULT_SAFETY_NETWORK_NUMBER == 0x1A2B
        assert DEFAULT_SNN == 0x1A2B
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 200.0

        assert UNDER_VOLTAGE_THRESHOLD_MV == 9000
        assert OVER_CURRENT_THRESHOLD_MA == 1500
        assert GROUND_LEAKAGE_THRESHOLD_MA == 10.0
        assert THERMAL_OVERLOAD_THRESHOLD_C == 85.0
        assert MAX_INRUSH_RATIO == 1.25
        assert MAX_DEENERGIZE_TIME_MS == 5.0

    def test_power_class_ratings_and_crc_polynomial_constants(self) -> None:
        """Verify nominal and maximum ratings across power classes and CRC polynomials."""
        assert CLASS_A_NOMINAL_VOLTAGE_MV == 24000
        assert CLASS_A_NOMINAL_CURRENT_MA == 20
        assert CLASS_A_MAX_POWER_MW == 500

        assert CLASS_C_NOMINAL_VOLTAGE_MV == 50000
        assert CLASS_C_NOMINAL_CURRENT_MA == 500
        assert CLASS_C_MAX_CURRENT_MA == 1000
        assert CLASS_C_MAX_POWER_MW == 50000

        assert CLASS_D_NOMINAL_VOLTAGE_MV == 24000
        assert CLASS_D_NOMINAL_CURRENT_MA == 20
        assert CLASS_D_MAX_CURRENT_MA == 380
        assert CLASS_D_MAX_POWER_MW == 500

        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CRC_INIT == 0xFFFF

    def test_diagnostic_codes_0xee21_through_0xee28(self) -> None:
        """Verify diagnostic code numerical assignments (0x0000, 0xEE21..0xEE28)."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_UNDER_VOLTAGE == 0xEE21
        assert DIAG_ERR_OVER_CURRENT == 0xEE22
        assert DIAG_ERR_GROUND_LEAKAGE == 0xEE23
        assert DIAG_ERR_THERMAL_OVERLOAD == 0xEE24
        assert DIAG_ERR_CRC_S1_FAULT == 0xEE25
        assert DIAG_ERR_CRC_S2_FAULT == 0xEE26
        assert DIAG_ERR_INRUSH_LIMIT_EXCEEDED == 0xEE27
        assert DIAG_ERR_FAIL_SAFE_TRIP == 0xEE28

        # Class attributes on DiagnosticCode
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.UNDER_VOLTAGE == 0xEE21
        assert DiagnosticCode.OVER_CURRENT == 0xEE22
        assert DiagnosticCode.GROUND_LEAKAGE == 0xEE23
        assert DiagnosticCode.THERMAL_OVERLOAD == 0xEE24
        assert DiagnosticCode.CRC_S1_FAULT == 0xEE25
        assert DiagnosticCode.CRC_S2_FAULT == 0xEE26
        assert DiagnosticCode.INRUSH_LIMIT_EXCEEDED == 0xEE27
        assert DiagnosticCode.FAIL_SAFE_TRIP == 0xEE28

        # Type aliases
        assert CipSafetyAplPowerDiagnosticCode is DiagnosticCode
        assert AplPowerDiagnosticCode is DiagnosticCode

    def test_diagnostic_code_signed_unsigned_representations(self) -> None:
        """Verify DiagnosticCode supports signed/unsigned equality, string, repr, and bitwise operations."""
        code = DIAG_ERR_UNDER_VOLTAGE  # 0xEE21
        assert int(code) == 0xEE21
        assert code == 0xEE21
        # Signed 16-bit representation: 0xEE21 - 0x10000 = -4575
        assert code == -4575
        assert (code & 0xFFFF) == 0xEE21
        assert (code & 0xFF00) == 0xEE00
        assert (0xFFFF & code) == 0xEE21
        assert str(code) == "0xEE21"
        assert repr(code) == "DiagnosticCode(0xEE21)"

        ok = DIAG_OK
        assert int(ok) == 0x0000
        assert ok == 0
        assert str(ok) == "0x0000"

        # Verify all fault codes have valid signed equivalents
        for raw_val in range(0xEE21, 0xEE29):
            diag = DiagnosticCode(raw_val)
            signed_equiv = raw_val - 0x10000
            assert diag == raw_val
            assert diag == signed_equiv

    def test_power_class_enum(self) -> None:
        """Verify PowerClass enum values and aliases."""
        assert PowerClass.CLASS_A == 1
        assert PowerClass.CLASS_C == 2
        assert PowerClass.CLASS_D == 3

        assert AplPowerClass is PowerClass
        assert CipSafetyAplPowerClass is PowerClass

    def test_power_operational_state_enum(self) -> None:
        """Verify PowerOperationalState enum values and aliases."""
        assert PowerOperationalState.INIT == 0
        assert PowerOperationalState.POWERED_NORMAL == 1
        assert PowerOperationalState.POWER_LIMIT == 2
        assert PowerOperationalState.FAULT_TRIP == 3

        assert CipSafetyAplPowerState is PowerOperationalState
        assert AplPowerOperationalState is PowerOperationalState
        assert PowerState is PowerOperationalState

    def test_status_bits_and_flags(self) -> None:
        """Verify CipSafetyAplPowerStatusBits bitmask flags and aliases."""
        assert CipSafetyAplPowerStatusBits.BUS_POWERED == 1 << 0
        assert CipSafetyAplPowerStatusBits.SAFE_OUTPUT_ENERGIZED == 1 << 1
        assert CipSafetyAplPowerStatusBits.INRUSH_ACTIVE == 1 << 2
        assert CipSafetyAplPowerStatusBits.GROUND_FAULT == 1 << 3
        assert CipSafetyAplPowerStatusBits.THERMAL_WARNING == 1 << 4
        assert CipSafetyAplPowerStatusBits.UNDER_VOLTAGE == 1 << 5
        assert CipSafetyAplPowerStatusBits.OVER_CURRENT == 1 << 6
        assert CipSafetyAplPowerStatusBits.CROWBAR_TRIPPED == 1 << 7

        assert CipSafetyAplPowerStatusBits.POWER_HEALTHY == (1 << 0) | (1 << 1)
        assert CipSafetyAplPowerStatusBits.FAULT_ACTIVE == (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7)

        assert PowerStatusBits is CipSafetyAplPowerStatusBits
        assert CipSafetyPowerStatusBits is CipSafetyAplPowerStatusBits

    def test_protocol_exceptions_hierarchy(self) -> None:
        """Verify custom protocol exception hierarchy."""
        assert issubclass(UnderVoltageError, CipSafetyAplPowerError)
        assert issubclass(OverCurrentError, CipSafetyAplPowerError)
        assert issubclass(GroundLeakageError, CipSafetyAplPowerError)
        assert issubclass(ThermalOverloadError, CipSafetyAplPowerError)
        assert issubclass(InrushLimitExceededError, CipSafetyAplPowerError)
        assert issubclass(CrcS1FaultError, CipSafetyAplPowerError)
        assert issubclass(CrcS2FaultError, CipSafetyAplPowerError)
        assert issubclass(CrowbarTrippedError, CipSafetyAplPowerError)
        assert issubclass(FailSafeTripError, CipSafetyAplPowerError)
        assert issubclass(CipSafetyAplPowerError, Exception)


# ============================================================================
# 2. TestDualSafetyCrcCalculation
# ============================================================================

class TestDualSafetyCrcCalculation:
    """Validate ODVA CIP Safety Dual CRC-S1 and CRC-S2 calculations and bit-flip sensitivity."""

    def test_crc_s1_and_crc_s2_calculation_determinism(self) -> None:
        """Verify deterministic CRC calculation and 16-bit range bounds."""
        payload = b"\x01\x02\x03\x04"
        crc1_a = calculate_crc_s1(payload)
        crc1_b = calculate_crc_s1(payload)
        assert crc1_a == crc1_b
        assert 0 <= crc1_a <= 0xFFFF

        crc2_a = calculate_crc_s2(1, 1000, 0x1A2B)
        crc2_b = calculate_crc_s2(1, 1000, 0x1A2B)
        assert crc2_a == crc2_b
        assert 0 <= crc2_a <= 0xFFFF

    def test_crc_s1_bit_flip_detection(self) -> None:
        """Verify single bit flip in any payload byte changes CRC-S1 checksum."""
        base_payload = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        base_crc = calculate_crc_s1(base_payload)

        for byte_idx in range(len(base_payload)):
            for bit_pos in range(8):
                mutated = bytearray(base_payload)
                mutated[byte_idx] ^= (1 << bit_pos)
                mutated_crc = calculate_crc_s1(bytes(mutated))
                assert mutated_crc != base_crc, f"Failed bit-flip detection at byte {byte_idx}, bit {bit_pos}"

    def test_crc_s2_header_inversion_and_tamper_detection(self) -> None:
        """Verify CRC-S2 alters on tampering sequence number, timestamp, or SNN."""
        base_seq = 10
        base_ts = 500000
        base_snn = 0x1A2B
        base_crc2 = calculate_crc_s2(base_seq, base_ts, base_snn)

        # Alter sequence number
        assert calculate_crc_s2(base_seq + 1, base_ts, base_snn) != base_crc2
        # Alter timestamp
        assert calculate_crc_s2(base_seq, base_ts + 1, base_snn) != base_crc2
        # Alter SNN
        assert calculate_crc_s2(base_seq, base_ts, base_snn ^ 0x0001) != base_crc2

    def test_crc_parameter_flexibility_and_aliases(self) -> None:
        """Verify compute_crc aliases and argument formats."""
        data = b"\x11\x22\x33"
        assert compute_crc_s1(data) == calculate_crc_s1(data)
        assert compute_crc_s1(payload=data) == calculate_crc_s1(data)
        assert compute_crc_s1(data=data) == calculate_crc_s1(data)

        assert compute_crc_s2(1, 2, 3) == calculate_crc_s2(1, 2, 3)
        assert compute_crc_s2(sequence_number=1, timestamp_us=2, safety_network_number=3) == calculate_crc_s2(1, 2, 3)

        with pytest.raises(ValueError):
            calculate_crc_s1(12345)

        with pytest.raises(ValueError):
            calculate_crc_s2("invalid")


# ============================================================================
# 3. TestCipSafetyAplPowerFrameModel
# ============================================================================

class TestCipSafetyAplPowerFrameModel:
    """Validate CipSafetyAplPowerFrame model, CRC computation, and tamper resistance."""

    def test_frame_initialization_defaults(self) -> None:
        """Verify frame default field assignments."""
        frame = CipSafetyAplPowerFrame()
        assert frame.power_class == PowerClass.CLASS_C
        assert frame.operational_state == PowerOperationalState.POWERED_NORMAL
        assert frame.voltage_mv == CLASS_C_NOMINAL_VOLTAGE_MV
        assert frame.current_ma == CLASS_C_NOMINAL_CURRENT_MA
        assert frame.consumed_mw == 25000
        assert frame.spur_mask == 0x00FF
        assert frame.sequence_number == 0
        assert frame.safety_network_number == DEFAULT_SAFETY_NETWORK_NUMBER

    def test_frame_crc_computation_and_validation(self) -> None:
        """Verify compute_crcs() and validate_crcs() / is_valid()."""
        frame = CipSafetyAplPowerFrame(
            sequence_number=5,
            timestamp_us=123456,
            safety_network_number=0x1A2B,
            payload=b"\xCA\xFE\xBA\xBE",
        )
        assert not frame.validate_crcs()
        frame.compute_crcs()
        assert frame.validate_crcs()
        assert frame.is_valid()
        assert frame.crc_s1 != 0
        assert frame.crc_s2 != 0

    def test_frame_tamper_detection(self) -> None:
        """Verify mutation helpers trigger validation failure."""
        frame = CipSafetyAplPowerFrame(payload=b"\x01\x02\x03\x04")
        frame.compute_crcs()
        assert frame.validate_crcs()

        # Mutate payload
        frame.mutate_payload(byte_offset=0, bit_pos=2)
        assert not frame.validate_crcs()

        # Recompute and mutate CRC-S1
        frame.compute_crcs()
        assert frame.validate_crcs()
        frame.mutate_crc_s1()
        assert not frame.validate_crcs()

        # Recompute and mutate CRC-S2
        frame.compute_crcs()
        assert frame.validate_crcs()
        frame.mutate_crc_s2()
        assert not frame.validate_crcs()

    def test_frame_serialization_round_trip(self) -> None:
        """Verify binary serialization and deserialization bit-exact round-trip."""
        frame = CipSafetyAplPowerFrame(
            power_class=PowerClass.CLASS_D,
            operational_state=PowerOperationalState.POWER_LIMIT,
            voltage_mv=24000,
            current_ma=250,
            consumed_mw=6000,
            spur_mask=0x00AA,
            sequence_number=1024,
            timestamp_us=98765432,
            safety_network_number=0x1A2B,
            payload=b"\xAA\xBB\xCC\xDD\xEE",
        )
        frame.compute_crcs()
        raw = frame.serialize()
        assert len(raw) >= 24

        deserialized = CipSafetyAplPowerFrame.deserialize(raw)
        assert deserialized.power_class == frame.power_class
        assert deserialized.operational_state == frame.operational_state
        assert deserialized.voltage_mv == frame.voltage_mv
        assert deserialized.current_ma == frame.current_ma
        assert deserialized.consumed_mw == frame.consumed_mw
        assert deserialized.spur_mask == frame.spur_mask
        assert deserialized.sequence_number == frame.sequence_number
        assert deserialized.timestamp_us == frame.timestamp_us
        assert deserialized.safety_network_number == frame.safety_network_number
        assert deserialized.payload == frame.payload
        assert deserialized.crc_s1 == frame.crc_s1
        assert deserialized.crc_s2 == frame.crc_s2
        assert deserialized.validate_crcs()

    def test_frame_deserialization_truncated_data(self) -> None:
        """Verify deserialization raises ValueError when payload is shorter than 24 bytes."""
        with pytest.raises(ValueError):
            CipSafetyAplPowerFrame.deserialize(b"\x00" * 16)


# ============================================================================
# 4. TestInrushCurrentLimiting
# ============================================================================

class TestInrushCurrentLimiting:
    """Validate inrush current monitoring, limit exceedance (< 1.25x), and recovery."""

    def test_inrush_within_limits_maintains_healthy_state(self) -> None:
        """Verify inrush current <= 1.25x steady state maintains healthy state."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.inrush_ratio = 1.15
        eng.inrush_active = True
        assert eng.is_healthy is True
        assert (eng.status_word & int(CipSafetyAplPowerStatusBits.INRUSH_ACTIVE)) != 0
        assert eng.diagnostic_code == DIAG_OK

    def test_inrush_exceedance_trip(self) -> None:
        """Verify inrush current > 1.25x triggers FAULT_TRIP and de-energizes safe outputs."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.inject_inrush_limit_exceeded(1.4)

        assert eng.inrush_ratio == 1.4
        assert eng.inrush_active is True
        assert eng.operational_state == PowerOperationalState.FAULT_TRIP
        assert eng.diagnostic_code == DIAG_ERR_INRUSH_LIMIT_EXCEEDED
        assert eng.diagnostic_code == 0xEE27
        assert eng.safe_output_energized is False
        assert eng.safe_output_data == b"\x00\x00\x00\x00"
        assert eng.is_healthy is False
        assert (eng.status_word & int(CipSafetyAplPowerStatusBits.INRUSH_ACTIVE)) != 0

    def test_inrush_recovery_via_clear_faults(self) -> None:
        """Verify clearing faults recovers from inrush trip."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.inject_inrush_limit_exceeded(1.35)
        assert eng.is_healthy is False

        eng.clear_faults()
        assert eng.inrush_ratio == 1.0
        assert eng.inrush_active is False
        assert eng.operational_state == PowerOperationalState.POWERED_NORMAL
        assert eng.diagnostic_code == DIAG_OK
        assert eng.safe_output_energized is True
        assert eng.is_healthy is True


# ============================================================================
# 5. TestUnderVoltageAndOverCurrentTrips
# ============================================================================

class TestUnderVoltageAndOverCurrentTrips:
    """Validate under-voltage (V < 9.0V) and over-current (I > 1.5A) trips and fast de-energization."""

    def test_under_voltage_trip_and_safe_output_clamp(self) -> None:
        """Verify under-voltage trip (Vbus < 9000 mV, 0xEE21) clamps safe output."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.inject_under_voltage(8500)

        assert eng.voltage_mv == 8500
        assert eng.diagnostic_code == DIAG_ERR_UNDER_VOLTAGE
        assert eng.diagnostic_code == 0xEE21
        assert eng.operational_state == PowerOperationalState.FAULT_TRIP
        assert eng.safe_output_energized is False
        assert eng.safe_output_data == b"\x00\x00\x00\x00"
        assert eng.last_fault_deenergize_time_ms < 5.0
        assert (eng.status_word & int(CipSafetyAplPowerStatusBits.UNDER_VOLTAGE)) != 0
        assert eng.is_healthy is False

        eng.clear_faults()
        assert eng.voltage_mv == 50000
        assert eng.diagnostic_code == DIAG_OK
        assert eng.is_healthy is True

    def test_over_current_trip_and_fast_deenergization(self) -> None:
        """Verify over-current trip (Ibus > 1500 mA, 0xEE22) de-energizes in < 5.0 ms."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.inject_over_current(1750)

        assert eng.current_ma == 1750
        assert eng.diagnostic_code == DIAG_ERR_OVER_CURRENT
        assert eng.diagnostic_code == 0xEE22
        assert eng.operational_state == PowerOperationalState.FAULT_TRIP
        assert eng.safe_output_energized is False
        assert eng.safe_output_data == b"\x00\x00\x00\x00"
        assert eng.last_fault_deenergize_time_ms < 5.0
        assert (eng.status_word & int(CipSafetyAplPowerStatusBits.OVER_CURRENT)) != 0
        assert eng.is_healthy is False

        eng.clear_faults()
        assert eng.current_ma == 500
        assert eng.diagnostic_code == DIAG_OK
        assert eng.is_healthy is True


# ============================================================================
# 6. TestGroundLeakageAndThermalOverloadTrips
# ============================================================================

class TestGroundLeakageAndThermalOverloadTrips:
    """Validate ground leakage (> 10mA) and thermal overload (> 85.0C) trips."""

    def test_ground_leakage_trip(self) -> None:
        """Verify ground leakage (> 10.0 mA, 0xEE23) triggers FAULT_TRIP."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.inject_ground_leakage(14.5)

        assert eng.ground_leakage_ma == 14.5
        assert eng.diagnostic_code == DIAG_ERR_GROUND_LEAKAGE
        assert eng.diagnostic_code == 0xEE23
        assert eng.operational_state == PowerOperationalState.FAULT_TRIP
        assert eng.safe_output_energized is False
        assert eng.safe_output_data == b"\x00\x00\x00\x00"
        assert (eng.status_word & int(CipSafetyAplPowerStatusBits.GROUND_FAULT)) != 0
        assert eng.is_healthy is False

        eng.clear_faults()
        assert eng.ground_leakage_ma == 0.0
        assert eng.diagnostic_code == DIAG_OK
        assert eng.is_healthy is True

    def test_thermal_overload_trip(self) -> None:
        """Verify thermal overload (> 85.0 C, 0xEE24) triggers FAULT_TRIP."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.inject_thermal_overload(91.5)

        assert eng.temperature_c == 91.5
        assert eng.diagnostic_code == DIAG_ERR_THERMAL_OVERLOAD
        assert eng.diagnostic_code == 0xEE24
        assert eng.operational_state == PowerOperationalState.FAULT_TRIP
        assert eng.safe_output_energized is False
        assert eng.safe_output_data == b"\x00\x00\x00\x00"
        assert (eng.status_word & int(CipSafetyAplPowerStatusBits.THERMAL_WARNING)) != 0
        assert eng.is_healthy is False

        eng.clear_faults()
        assert eng.temperature_c == 40.0
        assert eng.diagnostic_code == DIAG_OK
        assert eng.is_healthy is True


# ============================================================================
# 7. TestCrowbarTripAndFastDeenergization
# ============================================================================

class TestCrowbarTripAndFastDeenergization:
    """Validate crowbar protection circuit, safe state de-energization (< 5ms), and power cycling."""

    def test_crowbar_trip_execution(self) -> None:
        """Verify trip_crowbar() clamps bus voltage to 0V with de-energize time < 5ms."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.trip_crowbar()

        assert eng.crowbar_tripped is True
        assert eng.voltage_mv == 0
        assert eng.diagnostic_code == DIAG_ERR_FAIL_SAFE_TRIP
        assert eng.diagnostic_code == 0xEE28
        assert eng.operational_state == PowerOperationalState.FAULT_TRIP
        assert eng.safe_output_energized is False
        assert eng.safe_output_data == b"\x00\x00\x00\x00"
        assert eng.last_fault_deenergize_time_ms < 5.0
        assert (eng.status_word & int(CipSafetyAplPowerStatusBits.CROWBAR_TRIPPED)) != 0
        assert eng.is_healthy is False

    def test_power_off_and_power_on_cycling(self) -> None:
        """Verify power_off() de-energization and power_on() reactivation cycle."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.power_off()

        assert eng.bus_powered is False
        assert eng.safe_output_energized is False
        assert eng.voltage_mv == 0
        assert eng.current_ma == 0
        assert eng.consumed_mw == 0
        assert eng.safe_output_data == b"\x00\x00\x00\x00"
        assert eng.operational_state == PowerOperationalState.INIT
        assert eng.is_healthy is False

        eng.power_on()
        assert eng.bus_powered is True
        assert eng.safe_output_energized is True
        assert eng.voltage_mv == 50000
        assert eng.current_ma == 500
        assert eng.consumed_mw == 25000
        assert eng.operational_state == PowerOperationalState.POWERED_NORMAL
        assert eng.diagnostic_code == DIAG_OK
        assert eng.is_healthy is True


# ============================================================================
# 8. TestHornerOcsRegisterSynchronization
# ============================================================================

class TestHornerOcsRegisterSynchronization:
    """Validate bit-exact Horner OCS register space (%R2560..%R2567) and coil (%M597..%M598) synchronization."""

    def test_nominal_register_and_coil_synchronization(self) -> None:
        """Verify nominal synchronization matches bit-for-bit in %R2560..%R2567 and %M597..%M598."""
        rt = RegisterTable()
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C, register_table=rt)
        eng.sync_to_registers(rt, privilege=PrivilegeMode.USER)

        w_status = rt.read_word(REG_CIP_SAFETY_POWER_STATUS) & 0xFFFF
        w_volt = rt.read_word(REG_CIP_SAFETY_POWER_VOLTAGE_MV) & 0xFFFF
        w_curr = rt.read_word(REG_CIP_SAFETY_POWER_CURRENT_MA) & 0xFFFF
        w_pwr = rt.read_word(REG_CIP_SAFETY_POWER_CONSUMED_MW) & 0xFFFF
        w_spur = rt.read_word(REG_CIP_SAFETY_POWER_SPUR_MASK) & 0xFFFF
        w_diag = rt.read_word(REG_CIP_SAFETY_POWER_DIAGNOSTIC_CODE) & 0xFFFF
        w_word = rt.read_word(REG_CIP_SAFETY_POWER_STATUS_WORD) & 0xFFFF
        w_seq = rt.read_word(REG_CIP_SAFETY_POWER_SEQUENCE_COUNTER) & 0xFFFF
        b_healthy = rt.read_bit(COIL_CIP_SAFETY_POWER_HEALTHY)
        b_trip = rt.read_bit(COIL_CIP_SAFETY_POWER_TRIP)

        assert ((w_status >> 8) & 0xFF) == 2  # PowerClass.CLASS_C
        assert (w_status & 0xFF) == 1        # PowerOperationalState.POWERED_NORMAL
        assert w_volt == 50000
        assert w_curr == 500
        assert w_pwr == 25000
        assert w_spur == 0x00FF
        assert w_diag == 0x0000
        assert w_word == 0x0003  # BUS_POWERED | SAFE_OUTPUT_ENERGIZED
        assert w_seq == 0
        assert b_healthy is True
        assert b_trip is False

    def test_faulted_register_sync_states(self) -> None:
        """Verify register sync reflects faulted states for under-voltage, over-current, and crowbar trips."""
        rt = RegisterTable()
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C, register_table=rt)

        # Under-voltage fault sync
        eng.inject_under_voltage(8200)
        assert (rt.read_word(REG_CIP_SAFETY_POWER_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE21
        assert (rt.read_word(REG_CIP_SAFETY_POWER_STATUS_WORD) & int(CipSafetyAplPowerStatusBits.UNDER_VOLTAGE)) != 0
        assert rt.read_bit(COIL_CIP_SAFETY_POWER_HEALTHY) is False
        assert rt.read_bit(COIL_CIP_SAFETY_POWER_TRIP) is True

        # Over-current fault sync
        eng.inject_over_current(1600)
        assert (rt.read_word(REG_CIP_SAFETY_POWER_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE22
        assert (rt.read_word(REG_CIP_SAFETY_POWER_STATUS_WORD) & int(CipSafetyAplPowerStatusBits.OVER_CURRENT)) != 0
        assert rt.read_bit(COIL_CIP_SAFETY_POWER_HEALTHY) is False
        assert rt.read_bit(COIL_CIP_SAFETY_POWER_TRIP) is True

        # Crowbar trip sync
        eng.trip_crowbar()
        assert (rt.read_word(REG_CIP_SAFETY_POWER_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE28
        assert (rt.read_word(REG_CIP_SAFETY_POWER_STATUS_WORD) & int(CipSafetyAplPowerStatusBits.CROWBAR_TRIPPED)) != 0
        assert (rt.read_word(REG_CIP_SAFETY_POWER_VOLTAGE_MV) & 0xFFFF) == 0
        assert rt.read_bit(COIL_CIP_SAFETY_POWER_HEALTHY) is False
        assert rt.read_bit(COIL_CIP_SAFETY_POWER_TRIP) is True

    def test_register_sync_with_privilege_modes(self) -> None:
        """Verify register table synchronization succeeds under SYSTEM and USER privilege modes."""
        rt = RegisterTable()
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert (rt.read_word(REG_CIP_SAFETY_POWER_VOLTAGE_MV) & 0xFFFF) == 50000

        eng.sync_to_registers(rt, privilege=PrivilegeMode.USER)
        assert (rt.read_word(REG_CIP_SAFETY_POWER_VOLTAGE_MV) & 0xFFFF) == 50000


# ============================================================================
# 9. TestPureIEC61131StructuredTextAndSecurity
# ============================================================================

class TestPureIEC61131StructuredTextAndSecurity:
    """Validate pure IEC 61131-3 ST POU syntax and anti-ladder construct rejection."""

    def test_pure_st_pou_syntax_and_variable_bindings(self) -> None:
        """Verify CipSafetyAplPowerSync passes pure ST validation and binds all required registers."""
        assert verify_cip_safety_apl_power_pure_st() is True

        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_APL_POWER_SYNC)
        res = STParser.validate_code(ST_PROGRAM_CIP_SAFETY_APL_POWER_SYNC)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_APL_POWER_SYNC)
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R2560", "%R2561", "%R2562", "%R2563",
            "%R2564", "%R2565", "%R2566", "%R2567",
            "%M597", "%M598",
        }
        assert expected_regs.issubset(set(ast.bound_registers))
        assert CIP_SAFETY_APL_POWER_PURE_ST_POU == ST_PROGRAM_CIP_SAFETY_APL_POWER_SYNC
        assert CipSafetyAplPowerSync == ST_PROGRAM_CIP_SAFETY_APL_POWER_SYNC

    def test_strict_ladder_construct_rejection(self) -> None:
        """Verify immediate rejection of ladder contacts, coils, rungs, and mnemonics with LadderForbiddenError."""
        ladder_snippets = [
            "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[ ]--- x; END_PROGRAM",
            "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[/]--- x; END_PROGRAM",
            "PROGRAM LadderTest VAR y : BOOL; END_VAR ---( )--- y; END_PROGRAM",
            "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(S)--- y; END_PROGRAM",
            "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(R)--- y; END_PROGRAM",
            "PROGRAM LadderTest RUNG 1 END_PROGRAM",
            "PROGRAM LadderTest NETWORK 1 END_PROGRAM",
            "PROGRAM LadderTest XIC(Contact1); END_PROGRAM",
            "PROGRAM LadderTest OTE(Coil1); END_PROGRAM",
        ]
        for snippet in ladder_snippets:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# 10. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface compliance, ScanContext handling, and execution contract."""

    def test_ilogicunit_interface_inheritance(self) -> None:
        """Verify CipSafetyAplPowerEngine implements ILogicUnit properties."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        assert isinstance(eng, ILogicUnit)
        assert eng.name == "CipSafetyAplPowerEngine"
        assert eng.priority == 10
        assert eng.is_enabled is True

    def test_scan_step_with_context_and_table_resolution(self) -> None:
        """Verify scan_step propagates context.register_table before falling back to self.reg_table."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        rt_custom = RegisterTable()
        ctx = type("DummyContext", (), {"register_table": rt_custom, "dt_ms": 10.0})()

        res = eng.scan_step(ctx)
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert res.data["operational_state"] == "POWERED_NORMAL"
        assert res.data["is_healthy"] is True

        # Verify that custom table was populated
        assert (rt_custom.read_word(REG_CIP_SAFETY_POWER_VOLTAGE_MV) & 0xFFFF) == 50000

    def test_step_and_execute_methods(self) -> None:
        """Verify step() and execute() helper methods."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.step(dt=0.010)
        assert eng.cycles_count == 1

        res = eng.execute()
        assert isinstance(res, ExecutionResult)
        assert eng.cycles_count == 2

    def test_reset_method(self) -> None:
        """Verify reset() resets counters, frames, and clears faults."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.send_safety_frame()
        eng.inject_under_voltage(8000)
        assert eng.is_healthy is False
        assert eng.sequence_counter > 0

        eng.reset()
        assert eng.sequence_counter == 0
        assert eng.cycles_count == 0
        assert eng.time_since_last_heartbeat_ms == 0.0
        assert eng.last_tx_frame is None
        assert eng.last_rx_frame is None
        assert eng.is_healthy is True
        assert eng.diagnostic_code == DIAG_OK

    def test_auto_activate_false_initialization(self) -> None:
        """Verify initializing engine with auto_activate=False starts in unpowered INIT state."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C, auto_activate=False)
        assert eng.bus_powered is False
        assert eng.safe_output_energized is False
        assert eng.operational_state == PowerOperationalState.INIT
        assert eng.is_healthy is False


# ============================================================================
# 11. TestFrameTransmissionAndReception
# ============================================================================

class TestFrameTransmissionAndReception:
    """Validate safety power frame transmission, reception, and ingress error handling."""

    def test_send_and_receive_valid_frame(self) -> None:
        """Verify sending and receiving valid CIP safety power frames."""
        tx = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        rx = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)

        frame = tx.send_safety_frame(payload=b"\xCA\xFE\x01\x02")
        assert frame.validate_crcs()
        assert tx.sequence_counter == 1

        ok = rx.receive_safety_frame(frame)
        assert ok is True
        assert rx.safe_output_data == b"\xCA\xFE\x01\x02"
        assert rx.time_since_last_heartbeat_ms == 0.0
        assert rx.last_crc_s1_valid is True
        assert rx.last_crc_s2_valid is True

    def test_receive_frame_snn_mismatch(self) -> None:
        """Verify SNN mismatch trips fail-safe state with DIAG_ERR_FAIL_SAFE_TRIP."""
        tx = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C, safety_network_number=0x1111)
        rx = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C, safety_network_number=0x2222)

        frame = tx.send_safety_frame()
        ok = rx.receive_safety_frame(frame)
        assert ok is False
        assert rx.operational_state == PowerOperationalState.FAULT_TRIP
        assert rx.diagnostic_code == DIAG_ERR_FAIL_SAFE_TRIP

    def test_receive_frame_crc_s1_corruption(self) -> None:
        """Verify corrupted CRC-S1 in ingress frame trips DIAG_ERR_CRC_S1_FAULT."""
        tx = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        rx = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)

        frame = tx.send_safety_frame()
        frame.mutate_crc_s1()

        ok = rx.receive_safety_frame(frame)
        assert ok is False
        assert rx.last_crc_s1_valid is False
        assert rx.diagnostic_code == DIAG_ERR_CRC_S1_FAULT
        assert rx.diagnostic_code == 0xEE25

    def test_receive_frame_crc_s2_corruption(self) -> None:
        """Verify corrupted CRC-S2 in ingress frame trips DIAG_ERR_CRC_S2_FAULT."""
        tx = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        rx = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)

        frame = tx.send_safety_frame()
        frame.mutate_crc_s2()

        ok = rx.receive_safety_frame(frame)
        assert ok is False
        assert rx.last_crc_s2_valid is False
        assert rx.diagnostic_code == DIAG_ERR_CRC_S2_FAULT
        assert rx.diagnostic_code == 0xEE26

    def test_receive_frame_voltage_and_current_faults(self) -> None:
        """Verify ingress frame carrying under-voltage or over-current trips local engine."""
        tx = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        rx = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)

        # Ingress frame with under-voltage
        tx.voltage_mv = 8000
        frame_uv = tx.send_safety_frame()
        assert not rx.receive_safety_frame(frame_uv)
        assert rx.diagnostic_code == DIAG_ERR_UNDER_VOLTAGE

        rx.clear_faults()

        # Ingress frame with over-current
        tx.voltage_mv = 50000
        tx.current_ma = 1800
        frame_oc = tx.send_safety_frame()
        assert not rx.receive_safety_frame(frame_oc)
        assert rx.diagnostic_code == DIAG_ERR_OVER_CURRENT

    def test_receive_frame_when_bus_unpowered(self) -> None:
        """Verify receiving frame returns False when local engine bus is unpowered."""
        tx = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        rx = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C, auto_activate=False)

        frame = tx.send_safety_frame()
        assert not rx.receive_safety_frame(frame)

    def test_heartbeat_watchdog_feed(self) -> None:
        """Verify feed_heartbeat() and feed_watchdog() reset watchdog timer."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.time_since_last_heartbeat_ms = 150.0

        eng.feed_heartbeat()
        assert eng.time_since_last_heartbeat_ms == 0.0

        eng.time_since_last_heartbeat_ms = 180.0
        eng.feed_watchdog()
        assert eng.time_since_last_heartbeat_ms == 0.0


# ============================================================================
# 12. TestSoakAndMemoryStability
# ============================================================================

class TestSoakAndMemoryStability:
    """Validate 100-cycle soak execution with zero faults and stable memory consumption."""

    def test_100_cycle_soak_zero_faults_and_stable_memory(self) -> None:
        """Execute 100 continuous scan cycles verifying deterministic zero-fault behavior and stable memory."""
        rt = RegisterTable()
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C, register_table=rt)

        tracemalloc.start()
        snapshot_start = tracemalloc.take_snapshot()

        for cycle in range(1, 101):
            ctx = ScanContext(cycle=cycle, dt_ms=10.0, register_table=rt)
            res = eng.scan_step(ctx)
            assert res.status == AgentStatus.SUCCESS
            assert res.error_code is None
            assert eng.is_healthy is True
            assert eng.diagnostic_code == DIAG_OK
            assert eng.cycles_count == cycle

        snapshot_end = tracemalloc.take_snapshot()
        tracemalloc.stop()

        top_stats = snapshot_end.compare_to(snapshot_start, "lineno")
        total_growth_kb = sum(stat.size_diff for stat in top_stats) / 1024.0

        assert eng.cycles_count == 100
        assert total_growth_kb < 256.0, f"Memory growth exceeded limit: {total_growth_kb:.2f} KB"
        assert (rt.read_word(REG_CIP_SAFETY_POWER_VOLTAGE_MV) & 0xFFFF) == 50000
        assert rt.read_bit(COIL_CIP_SAFETY_POWER_HEALTHY) is True
        assert rt.read_bit(COIL_CIP_SAFETY_POWER_TRIP) is False


# ============================================================================
# 13. TestNineStageVerificationRunner
# ============================================================================

class TestNineStageVerificationRunner:
    """Validate complete 9-stage verification runner and strict 4-state engineering contract."""

    def test_verification_runner_execution(self) -> None:
        """Verify run_cip_safety_apl_power_verification returns strict 4-state 'success' with 9/9 stages passed."""
        report = run_cip_safety_apl_power_verification()
        assert isinstance(report, dict)
        assert report["status"] == "success"
        assert report["error_code"] is None
        assert report["stages_passed"] == 9
        assert report["total_stages"] == 9

        stages = report["data"]["stages"]
        assert len(stages) == 9
        for stage in stages:
            assert stage["passed"] is True
            assert stage["timing_ms"] >= 0.0
            assert "details" in stage

    def test_verification_runner_artifact_generation(self) -> None:
        """Verify verification runner writes valid JSON evidence file."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "test_power_evidence.json"
            report = run_cip_safety_apl_power_verification(output_path=out_file)
            assert out_file.exists()
            assert out_file.stat().st_size > 0

            with open(out_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["stages_passed"] == 9
            assert loaded["data"]["work_package"] == "W295"


# ============================================================================
# 14. TestPowerClassesAndEdgeCases
# ============================================================================

class TestPowerClassesAndEdgeCases:
    """Validate power class options, consumed_mw calculation, and fail-safe trips."""

    def test_power_class_a_and_d_configurations(self) -> None:
        """Verify PowerClass A and D nominal values and power metrics."""
        eng_a = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_A)
        assert eng_a.power_class == PowerClass.CLASS_A
        assert eng_a.voltage_mv == 24000
        assert eng_a.current_ma == 20
        assert eng_a.consumed_mw == 480
        assert ((eng_a.power_status >> 8) & 0xFF) == 1

        eng_d = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_D)
        assert eng_d.power_class == PowerClass.CLASS_D
        assert eng_d.voltage_mv == 24000
        assert eng_d.current_ma == 20
        assert eng_d.consumed_mw == 480
        assert ((eng_d.power_status >> 8) & 0xFF) == 3

    def test_consumed_mw_property_and_setter(self) -> None:
        """Verify consumed_mw calculation and manual override."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        assert eng.consumed_mw == 25000
        eng.consumed_mw = 32000
        assert eng.consumed_mw == 32000
        eng.consumed_mw = None
        assert eng.consumed_mw == 25000

    def test_trip_fail_safe_custom_code(self) -> None:
        """Verify trip_fail_safe sets custom diagnostic code and transitions state."""
        eng = CipSafetyAplPowerEngine(power_class=PowerClass.CLASS_C)
        eng.trip_fail_safe(DIAG_ERR_CRC_S1_FAULT)
        assert eng.operational_state == PowerOperationalState.FAULT_TRIP
        assert eng.diagnostic_code == DIAG_ERR_CRC_S1_FAULT
        assert eng.safe_output_energized is False
        assert eng.is_healthy is False
