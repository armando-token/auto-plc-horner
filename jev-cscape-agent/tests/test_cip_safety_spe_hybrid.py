"""Comprehensive Unit Test Suite for Wave W298 CIP Safety Over Single-Pair Ethernet (SPE) Hybrid Power and Data.

Work Package: W298 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Standards: IEEE 802.3cg 10BASE-T1L, IEEE 802.3bu / IEEE 802.3cg SPoE / PoDL Classes 10-15, ODVA CIP Safety Volume 5 (IEC 61784-3-2 / IEC 61508 SIL 3).

Covers Comprehensive Deterministic Unit Tests across 13 Mandatory Test Classes (70 Tests):
1. TestConstantsEnumsAndDiagnosticCodes: Protocol constants, register mappings (%R2590..%R2597),
   discrete coils (%M604..%M605), extended register aliases, diagnostic codes (0x0000, 0xEE31..0xEE37),
   signed/unsigned 16-bit representations, bitwise behavior, PowerClass and SafetyConnectionState enums,
   CipSafetySpeHybridStatusBits, and protocol exceptions hierarchy.
2. TestDualSafetyCrcCalculation: CRC-S1 (polynomial 0x5935) and CRC-S2 (polynomial 0x755B inverted header)
   calculation, determinism, 16-bit bounds, single-bit flip sensitivity, header field tampering detection,
   compute_crc aliases, and parameter validation.
3. TestCipSafetySpeHybridFrameModel: Frame model defaults, CRC generation and verification,
   payload corruption mutation, CRC-S1 / CRC-S2 mutation, binary serialization and deserialization bit-exact round-trip,
   and truncated payload error handling.
4. TestPowerClassesAndLimits: Verification of all 6 SPoE / PoDL Power Classes (Classes 10-15),
   voltage boundaries (20-30V for 10-12, 50-58V for 13-15), power limits (1.23W..52.0W),
   nominal voltage & power calculations, consumed_mw property setter override, and loop resistance calculations.
5. TestConnectionStateMachine: Connection state transitions (IDLE -> CONNECTING -> RUNNING -> FAULT),
   connect(), complete_connection(), disconnect(), trip_fail_safe(), clear_faults(), reset(),
   feed_heartbeat(), and watchdog timeout surveillance.
6. TestUnderVoltageAndOverCurrentTrips: Bus under-voltage trip (V < 18.0V, 0xEE31), status bit assertion,
   bus over-current trip (I > 1.85A, 0xEE32), safe de-energization in < 5.0 ms, and fault recovery.
7. TestHighLoopResistanceAndGroundLeakageTrips: Line loop resistance surveillance (> 65.0 Ohm, 0xEE33),
   ground leakage surveillance (> 5.0 mA, 0xEE34), status word flags, and clean recovery.
8. TestFrameTransmissionAndReception: Safety frame construction, transmission sequence incrementation,
   reception validation, Safety Network Number (SNN) mismatch interception, CRC-S1 / CRC-S2 corruption interception,
   ingress threshold violation interception, and heartbeat watchdog reset.
9. TestHornerOcsRegisterSynchronization: Bit-exact synchronization to Horner OCS analog registers (%R2590..%R2597)
   and discrete coils (%M604..%M605) across nominal and faulted states, signed 16-bit masking `(rt.read_word(...) & 0xFFFF) == expected`,
   bit-packing, privilege modes, and coil exclusivity.
10. TestILogicUnitCompliance: ILogicUnit interface compliance (scan_step, step, execute, reset), ScanContext and
    RegisterTable propagation hierarchy, ExecutionResult contract validation, and unpowered initialization.
11. TestPureIEC61131StructuredTextAndSecurity: Pure IEC 61131-3 Structured Text POU CipSafetySpeHybridSync syntax
    validation via STParser and SecurityGuard, variable address bindings, and strict rejection of ladder logic constructs
    (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
12. TestSoakAndMemoryStability: 100-cycle continuous scan soak test with zero fault trips, 100% SUCCESS outcomes,
    monotonic counter increments, and stable memory footprint verified via tracemalloc.
13. TestNineStageVerificationRunner: Complete 9-stage verification suite run_cip_safety_spe_hybrid_verification,
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
from jev_cscape.telemetry.cip_safety_spe_hybrid import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_SPE_HYBRID_CLASS_ID,
    DEFAULT_SAFETY_NETWORK_NUMBER,
    DEFAULT_SNN,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    UNDER_VOLTAGE_THRESHOLD_MV,
    OVER_CURRENT_THRESHOLD_MA,
    HIGH_LOOP_RESISTANCE_THRESHOLD_MOHM,
    GROUND_LEAKAGE_THRESHOLD_MA,
    MAX_DEENERGIZE_TIME_MS,
    DEFAULT_VOLTAGE_MV,
    DEFAULT_CURRENT_MA,
    DEFAULT_LOOP_RESISTANCE_MOHM,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CRC_INIT,
    REG_CIP_SAFETY_SPE_VOLTAGE_MV,
    REG_CIP_SAFETY_SPE_CURRENT_MA,
    REG_CIP_SAFETY_SPE_POWER_MW,
    REG_CIP_SAFETY_SPE_LOOP_RESISTANCE_MOHM,
    REG_CIP_SAFETY_SPE_STATUS_WORD,
    REG_CIP_SAFETY_SPE_DIAGNOSTIC_CODE,
    REG_CIP_SAFETY_SPE_ERROR_COUNT,
    REG_CIP_SAFETY_SPE_SEQUENCE_COUNTER,
    REG_SPE_HYBRID_VOLTAGE_MV,
    REG_SPE_HYBRID_CURRENT_MA,
    REG_SPE_HYBRID_POWER_MW,
    REG_SPE_HYBRID_LOOP_RESISTANCE_MOHM,
    REG_SPE_HYBRID_STATUS_WORD,
    REG_SPE_HYBRID_DIAGNOSTIC_CODE,
    REG_SPE_HYBRID_ERROR_COUNT,
    REG_SPE_HYBRID_SEQUENCE_COUNTER,
    REG_CIP_SAFETY_SPE_HYBRID_VOLTAGE_MV,
    REG_CIP_SAFETY_SPE_HYBRID_CURRENT_MA,
    REG_CIP_SAFETY_SPE_HYBRID_POWER_MW,
    REG_CIP_SAFETY_SPE_HYBRID_LOOP_RESISTANCE_MOHM,
    REG_CIP_SAFETY_SPE_HYBRID_STATUS_WORD,
    REG_CIP_SAFETY_SPE_HYBRID_DIAGNOSTIC_CODE,
    REG_CIP_SAFETY_SPE_ERROR_COUNT as REG_CIP_SAFETY_SPE_HYBRID_ERROR_COUNT,
    REG_CIP_SAFETY_SPE_SEQUENCE_COUNTER as REG_CIP_SAFETY_SPE_HYBRID_SEQUENCE_COUNTER,
    COIL_CIP_SAFETY_SPE_POWER_ENABLE,
    COIL_CIP_SAFETY_SPE_TRIP,
    COIL_SPE_HYBRID_POWER_ENABLE,
    COIL_SPE_HYBRID_TRIP,
    COIL_CIP_SAFETY_SPE_HYBRID_HEALTHY,
    COIL_CIP_SAFETY_SPE_HYBRID_TRIP,
    COIL_CIP_SAFETY_SPE_HEALTHY,
    DiagnosticCode,
    DIAG_OK,
    DIAG_ERR_UNDER_VOLTAGE,
    DIAG_ERR_OVER_CURRENT,
    DIAG_ERR_HIGH_LOOP_RESISTANCE,
    DIAG_ERR_GROUND_LEAKAGE,
    DIAG_ERR_TIMEOUT,
    DIAG_ERR_CRC_S1,
    DIAG_ERR_CRC_S2,
    DIAG_ERR_CRC_S1_FAULT,
    DIAG_ERR_CRC_S2_FAULT,
    DIAG_ERR_WATCHDOG_TIMEOUT,
    CipSafetySpeHybridDiagnosticCode,
    SpeHybridDiagnosticCode,
    PowerClass,
    SPoEPowerClass,
    PoDLPowerClass,
    SpeHybridPowerClass,
    SafetyConnectionState,
    CipSafetySpeHybridState,
    SpeHybridState,
    ConnectionState,
    CipSafetyState,
    CipSafetySpeHybridStatusBits,
    SpeHybridStatusBits,
    CipSafetySpeHybridError,
    UnderVoltageError,
    OverCurrentError,
    HighLoopResistanceError,
    GroundLeakageError,
    TimeoutError,
    CrcS1FaultError,
    CrcS2FaultError,
    SpeHybridUnderVoltageError,
    SpeHybridOverCurrentError,
    SpeHybridHighLoopResistanceError,
    SpeHybridGroundLeakageError,
    SpeHybridTimeoutError,
    SpeHybridCrcS1Error,
    SpeHybridCrcS2Error,
    calculate_crc_s1,
    calculate_crc_s2,
    compute_crc_s1,
    compute_crc_s2,
    CipSafetySpeHybridFrame,
    CIPSafetySpeHybridFrame,
    CIPSafetySPEHybridFrame,
    SpeHybridFrame,
    CipSafetySpeHybridEngine,
    CIPSafetySpeHybridEngine,
    CIPSafetySPEHybridEngine,
    SPESafetyHybridEngine,
    SpeHybridEngine,
    ST_PROGRAM_CIP_SAFETY_SPE_HYBRID_SYNC,
    CIP_SAFETY_SPE_HYBRID_PURE_ST_POU,
    CIP_SAFETY_SPE_HYBRID_SYNC_POU,
    CipSafetySpeHybridSync,
    verify_cip_safety_spe_hybrid_pure_st,
    run_cip_safety_spe_hybrid_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnosticCodes
# ============================================================================

class TestConstantsEnumsAndDiagnosticCodes:
    """Validate protocol constants, register mappings, coils, enums, diagnostic codes, and exceptions."""

    def test_class_ids_and_defaults(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_SPE_HYBRID_CLASS_ID == 0x42
        assert DEFAULT_SAFETY_NETWORK_NUMBER == 0x1A2B
        assert DEFAULT_SNN == 0x1A2B
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 200.0

    def test_thresholds(self) -> None:
        assert UNDER_VOLTAGE_THRESHOLD_MV == 18000
        assert OVER_CURRENT_THRESHOLD_MA == 1850
        assert HIGH_LOOP_RESISTANCE_THRESHOLD_MOHM == 65000
        assert GROUND_LEAKAGE_THRESHOLD_MA == 5.0
        assert MAX_DEENERGIZE_TIME_MS == 5.0

    def test_register_and_coil_mappings(self) -> None:
        assert REG_CIP_SAFETY_SPE_VOLTAGE_MV == "%R2590"
        assert REG_CIP_SAFETY_SPE_CURRENT_MA == "%R2591"
        assert REG_CIP_SAFETY_SPE_POWER_MW == "%R2592"
        assert REG_CIP_SAFETY_SPE_LOOP_RESISTANCE_MOHM == "%R2593"
        assert REG_CIP_SAFETY_SPE_STATUS_WORD == "%R2594"
        assert REG_CIP_SAFETY_SPE_DIAGNOSTIC_CODE == "%R2595"
        assert REG_CIP_SAFETY_SPE_ERROR_COUNT == "%R2596"
        assert REG_CIP_SAFETY_SPE_SEQUENCE_COUNTER == "%R2597"

        assert COIL_CIP_SAFETY_SPE_POWER_ENABLE == "%M604"
        assert COIL_CIP_SAFETY_SPE_TRIP == "%M605"

    def test_extended_register_and_coil_aliases(self) -> None:
        assert REG_SPE_HYBRID_VOLTAGE_MV == "%R2590"
        assert REG_SPE_HYBRID_CURRENT_MA == "%R2591"
        assert REG_SPE_HYBRID_POWER_MW == "%R2592"
        assert REG_SPE_HYBRID_LOOP_RESISTANCE_MOHM == "%R2593"
        assert REG_SPE_HYBRID_STATUS_WORD == "%R2594"
        assert REG_SPE_HYBRID_DIAGNOSTIC_CODE == "%R2595"
        assert REG_SPE_HYBRID_ERROR_COUNT == "%R2596"
        assert REG_SPE_HYBRID_SEQUENCE_COUNTER == "%R2597"

        assert REG_CIP_SAFETY_SPE_HYBRID_VOLTAGE_MV == "%R2590"
        assert REG_CIP_SAFETY_SPE_HYBRID_CURRENT_MA == "%R2591"
        assert REG_CIP_SAFETY_SPE_HYBRID_POWER_MW == "%R2592"
        assert REG_CIP_SAFETY_SPE_HYBRID_LOOP_RESISTANCE_MOHM == "%R2593"
        assert REG_CIP_SAFETY_SPE_HYBRID_STATUS_WORD == "%R2594"
        assert REG_CIP_SAFETY_SPE_HYBRID_DIAGNOSTIC_CODE == "%R2595"

        assert COIL_SPE_HYBRID_POWER_ENABLE == "%M604"
        assert COIL_SPE_HYBRID_TRIP == "%M605"
        assert COIL_CIP_SAFETY_SPE_HYBRID_HEALTHY == "%M604"
        assert COIL_CIP_SAFETY_SPE_HYBRID_TRIP == "%M605"
        assert COIL_CIP_SAFETY_SPE_HEALTHY == "%M604"

    def test_diagnostic_codes_representation_and_equality(self) -> None:
        codes = [
            (DIAG_OK, 0x0000),
            (DIAG_ERR_UNDER_VOLTAGE, 0xEE31),
            (DIAG_ERR_OVER_CURRENT, 0xEE32),
            (DIAG_ERR_HIGH_LOOP_RESISTANCE, 0xEE33),
            (DIAG_ERR_GROUND_LEAKAGE, 0xEE34),
            (DIAG_ERR_TIMEOUT, 0xEE35),
            (DIAG_ERR_CRC_S1, 0xEE36),
            (DIAG_ERR_CRC_S2, 0xEE37),
        ]
        for diag_obj, val in codes:
            assert int(diag_obj) == val
            assert diag_obj == val
            # Signed 16-bit representation equality
            signed_val = val - 0x10000 if val >= 0x8000 else val
            assert diag_obj == signed_val
            assert (diag_obj & 0xFFFF) == val
            assert 0xFFFF & diag_obj == val
            assert hash(diag_obj) == hash(val)
            assert str(val) in repr(diag_obj) or f"0x{val:04X}" in repr(diag_obj)

    def test_all_diagnostic_codes_individual_values(self) -> None:
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_UNDER_VOLTAGE == 0xEE31
        assert DIAG_ERR_OVER_CURRENT == 0xEE32
        assert DIAG_ERR_HIGH_LOOP_RESISTANCE == 0xEE33
        assert DIAG_ERR_GROUND_LEAKAGE == 0xEE34
        assert DIAG_ERR_TIMEOUT == 0xEE35
        assert DIAG_ERR_CRC_S1 == 0xEE36
        assert DIAG_ERR_CRC_S2 == 0xEE37
        assert DIAG_ERR_CRC_S1_FAULT == 0xEE36
        assert DIAG_ERR_CRC_S2_FAULT == 0xEE37
        assert DIAG_ERR_WATCHDOG_TIMEOUT == 0xEE35

    def test_power_class_enums(self) -> None:
        assert PowerClass.CLASS_10 == 10
        assert PowerClass.CLASS_11 == 11
        assert PowerClass.CLASS_12 == 12
        assert PowerClass.CLASS_13 == 13
        assert PowerClass.CLASS_14 == 14
        assert PowerClass.CLASS_15 == 15

        # Classes 10-12 voltage & power limits
        for pc, pwr_mw in [
            (PowerClass.CLASS_10, 1230),
            (PowerClass.CLASS_11, 3200),
            (PowerClass.CLASS_12, 8400),
        ]:
            assert pc.min_voltage_mv == 20000
            assert pc.max_voltage_mv == 30000
            assert pc.nominal_voltage_mv == 24000
            assert pc.max_power_mw == pwr_mw

        # Classes 13-15 voltage & power limits
        for pc, pwr_mw in [
            (PowerClass.CLASS_13, 15300),
            (PowerClass.CLASS_14, 30000),
            (PowerClass.CLASS_15, 52000),
        ]:
            assert pc.min_voltage_mv == 50000
            assert pc.max_voltage_mv == 58000
            assert pc.nominal_voltage_mv == 54000
            assert pc.max_power_mw == pwr_mw

    def test_connection_state_enums(self) -> None:
        assert SafetyConnectionState.IDLE == 0
        assert SafetyConnectionState.CONNECTING == 1
        assert SafetyConnectionState.RUNNING == 2
        assert SafetyConnectionState.FAULT == 3

        assert CipSafetySpeHybridState is SafetyConnectionState
        assert SpeHybridState is SafetyConnectionState
        assert ConnectionState is SafetyConnectionState
        assert CipSafetyState is SafetyConnectionState

    def test_status_bits_definitions(self) -> None:
        assert CipSafetySpeHybridStatusBits.POWER_ENABLE == 1 << 0
        assert CipSafetySpeHybridStatusBits.RUNNING == 1 << 1
        assert CipSafetySpeHybridStatusBits.CONNECTING == 1 << 2
        assert CipSafetySpeHybridStatusBits.UNDER_VOLTAGE == 1 << 3
        assert CipSafetySpeHybridStatusBits.OVER_CURRENT == 1 << 4
        assert CipSafetySpeHybridStatusBits.HIGH_LOOP_RESISTANCE == 1 << 5
        assert CipSafetySpeHybridStatusBits.GROUND_LEAKAGE == 1 << 6
        assert CipSafetySpeHybridStatusBits.TIMEOUT == 1 << 7
        assert CipSafetySpeHybridStatusBits.CRC_S1_FAULT == 1 << 8
        assert CipSafetySpeHybridStatusBits.CRC_S2_FAULT == 1 << 9
        assert CipSafetySpeHybridStatusBits.FAULT_TRIP == 1 << 10

    def test_exceptions_hierarchy(self) -> None:
        assert issubclass(UnderVoltageError, CipSafetySpeHybridError)
        assert issubclass(OverCurrentError, CipSafetySpeHybridError)
        assert issubclass(HighLoopResistanceError, CipSafetySpeHybridError)
        assert issubclass(GroundLeakageError, CipSafetySpeHybridError)
        assert issubclass(TimeoutError, CipSafetySpeHybridError)
        assert issubclass(CrcS1FaultError, CipSafetySpeHybridError)
        assert issubclass(CrcS2FaultError, CipSafetySpeHybridError)


# ============================================================================
# 2. TestDualSafetyCrcCalculation
# ============================================================================

class TestDualSafetyCrcCalculation:
    """Validate 16-bit CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B) calculation and integrity."""

    def test_crc_polynomial_constants(self) -> None:
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CRC_INIT == 0xFFFF

    def test_crc_s1_determinism_and_bounds(self) -> None:
        data = b"\x01\x02\x03\x04\x05\x06"
        c1 = calculate_crc_s1(data)
        assert 0 <= c1 <= 0xFFFF
        assert c1 == calculate_crc_s1(data)
        assert c1 == compute_crc_s1(data)

    def test_crc_s2_determinism_and_bounds(self) -> None:
        c2 = calculate_crc_s2(100, 500000, 0x1A2B)
        assert 0 <= c2 <= 0xFFFF
        assert c2 == calculate_crc_s2(100, 500000, 0x1A2B)
        assert c2 == compute_crc_s2(100, 500000, 0x1A2B)

    def test_crc_s1_single_bit_sensitivity(self) -> None:
        base = bytearray(b"\x10\x20\x30\x40\x50")
        c_base = calculate_crc_s1(bytes(base))
        for byte_idx in range(len(base)):
            for bit_idx in range(8):
                mutated = bytearray(base)
                mutated[byte_idx] ^= (1 << bit_idx)
                c_mut = calculate_crc_s1(bytes(mutated))
                assert c_mut != c_base, f"Failed bitflip detection at byte {byte_idx}, bit {bit_idx}"

    def test_crc_s2_header_field_sensitivity(self) -> None:
        base_s2 = calculate_crc_s2(10, 1000, 0x1A2B)
        # Sequence mismatch
        assert calculate_crc_s2(11, 1000, 0x1A2B) != base_s2
        # Timestamp mismatch
        assert calculate_crc_s2(10, 1001, 0x1A2B) != base_s2
        # SNN mismatch
        assert calculate_crc_s2(10, 1000, 0x1A2C) != base_s2

    def test_crc_argument_handling(self) -> None:
        c_bytes = calculate_crc_s1(b"\xAA\xBB")
        c_kwargs = calculate_crc_s1(payload=b"\xAA\xBB")
        assert c_bytes == c_kwargs

        c2_args = calculate_crc_s2(1, 2, 3)
        c2_kwargs = calculate_crc_s2(sequence_number=1, timestamp_us=2, safety_network_number=3)
        assert c2_args == c2_kwargs

    def test_crc_empty_payload(self) -> None:
        c1_empty = calculate_crc_s1(b"")
        assert 0 <= c1_empty <= 0xFFFF
        assert c1_empty == calculate_crc_s1(payload=b"")

    def test_crc_invalid_arguments_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            calculate_crc_s1("invalid_string_type")
        with pytest.raises(ValueError):
            calculate_crc_s2("invalid")


# ============================================================================
# 3. TestCipSafetySpeHybridFrameModel
# ============================================================================

class TestCipSafetySpeHybridFrameModel:
    """Validate CipSafetySpeHybridFrame serialization, dual CRC generation, and bit mutation."""

    def test_frame_defaults(self) -> None:
        frame = CipSafetySpeHybridFrame()
        assert frame.power_class == PowerClass.CLASS_12
        assert frame.state == SafetyConnectionState.RUNNING
        assert frame.voltage_mv == 24000
        assert frame.current_ma == 500
        assert frame.power_mw == 12000
        assert frame.loop_resistance_mohm == 2000

    def test_frame_crc_generation_and_validation(self) -> None:
        frame = CipSafetySpeHybridFrame(payload=b"\x01\x02\x03\x04")
        frame.compute_crcs()
        assert frame.crc_s1 != 0
        assert frame.crc_s2 != 0
        assert frame.validate_crcs() is True
        assert frame.is_valid() is True

    def test_frame_serialization_round_trip(self) -> None:
        frame = CipSafetySpeHybridFrame(
            power_class=PowerClass.CLASS_14,
            state=SafetyConnectionState.RUNNING,
            voltage_mv=54000,
            current_ma=600,
            power_mw=32400,
            loop_resistance_mohm=2500,
            sequence_number=42,
            timestamp_us=123456,
            safety_network_number=0x1A2B,
            payload=b"\xDE\xAD\xBE\xEF",
        )
        frame.compute_crcs()
        serialized = frame.serialize()
        assert len(serialized) == 20 + len(frame.payload) + 4

        restored = CipSafetySpeHybridFrame.deserialize(serialized)
        assert restored.power_class == frame.power_class
        assert restored.state == frame.state
        assert restored.voltage_mv == frame.voltage_mv
        assert restored.current_ma == frame.current_ma
        assert restored.power_mw == frame.power_mw
        assert restored.loop_resistance_mohm == frame.loop_resistance_mohm
        assert restored.sequence_number == frame.sequence_number
        assert restored.timestamp_us == frame.timestamp_us
        assert restored.safety_network_number == frame.safety_network_number
        assert restored.payload == frame.payload
        assert restored.crc_s1 == frame.crc_s1
        assert restored.crc_s2 == frame.crc_s2
        assert restored.validate_crcs() is True

    def test_frame_mutations(self) -> None:
        frame = CipSafetySpeHybridFrame(payload=b"\x11\x22\x33\x44")
        frame.compute_crcs()

        # Mutate payload
        frame.mutate_payload(byte_offset=0, bit_pos=0)
        assert frame.validate_crcs() is False

        # Reset & mutate CRC-S1
        frame.payload = b"\x11\x22\x33\x44"
        frame.compute_crcs()
        frame.mutate_crc_s1()
        assert frame.validate_crcs() is False

        # Reset & mutate CRC-S2
        frame.compute_crcs()
        frame.mutate_crc_s2()
        assert frame.validate_crcs() is False

    def test_deserialize_too_short(self) -> None:
        with pytest.raises(ValueError):
            CipSafetySpeHybridFrame.deserialize(b"\x00" * 20)

    def test_frame_is_valid_alias(self) -> None:
        frame = CipSafetySpeHybridFrame(payload=b"\x0A\x0B\x0C")
        frame.compute_crcs()
        assert frame.is_valid() == frame.validate_crcs()


# ============================================================================
# 4. TestPowerClassesAndLimits
# ============================================================================

class TestPowerClassesAndLimits:
    """Validate SPoE / PoDL Power Classes 10-15 and engine electrical calculations."""

    def test_all_six_power_classes(self) -> None:
        assert PowerClass.CLASS_10.max_power_mw == 1230
        assert PowerClass.CLASS_11.max_power_mw == 3200
        assert PowerClass.CLASS_12.max_power_mw == 8400
        assert PowerClass.CLASS_13.max_power_mw == 15300
        assert PowerClass.CLASS_14.max_power_mw == 30000
        assert PowerClass.CLASS_15.max_power_mw == 52000

    def test_power_classes_power_in_watts(self) -> None:
        assert PowerClass.CLASS_10.max_power_w == pytest.approx(1.23, rel=1e-3)
        assert PowerClass.CLASS_11.max_power_w == pytest.approx(3.2, rel=1e-3)
        assert PowerClass.CLASS_12.max_power_w == pytest.approx(8.4, rel=1e-3)
        assert PowerClass.CLASS_13.max_power_w == pytest.approx(15.3, rel=1e-3)
        assert PowerClass.CLASS_14.max_power_w == pytest.approx(30.0, rel=1e-3)
        assert PowerClass.CLASS_15.max_power_w == pytest.approx(52.0, rel=1e-3)

    def test_engine_power_initialization_per_class(self) -> None:
        for pc in [PowerClass.CLASS_10, PowerClass.CLASS_11, PowerClass.CLASS_12]:
            eng = CipSafetySpeHybridEngine(power_class=pc)
            assert eng.voltage_mv == 24000
            assert eng.power_mw == (24000 * 500) // 1000

        for pc in [PowerClass.CLASS_13, PowerClass.CLASS_14, PowerClass.CLASS_15]:
            eng = CipSafetySpeHybridEngine(power_class=pc)
            assert eng.voltage_mv == 54000
            assert eng.power_mw == (54000 * 500) // 1000

    def test_consumed_mw_getter_setter(self) -> None:
        eng = CipSafetySpeHybridEngine()
        assert eng.power_mw == 12000
        eng.power_mw = 15000
        assert eng.power_mw == 15000
        eng.power_mw = None
        assert eng.power_mw == 12000

    def test_loop_resistance_calculations(self) -> None:
        eng = CipSafetySpeHybridEngine(loop_resistance_mohm=3500)
        assert eng.loop_resistance_mohm == 3500
        assert eng.is_healthy is True
        # Boundary check: 65000 mOhm is acceptable
        eng.loop_resistance_mohm = 65000
        assert eng.is_healthy is True
        # Above threshold: trips fault
        eng.inject_high_loop_resistance(65001)
        assert eng.is_healthy is False
        assert eng.diagnostic_code == DIAG_ERR_HIGH_LOOP_RESISTANCE


# ============================================================================
# 5. TestConnectionStateMachine
# ============================================================================

class TestConnectionStateMachine:
    """Validate CIP Safety Connection State Machine transitions (IDLE, CONNECTING, RUNNING, FAULT)."""

    def test_initial_state_auto_activate(self) -> None:
        eng_auto = CipSafetySpeHybridEngine(auto_activate=True)
        assert eng_auto.state == SafetyConnectionState.RUNNING
        assert eng_auto.power_enabled is True

        eng_manual = CipSafetySpeHybridEngine(auto_activate=False)
        assert eng_manual.state == SafetyConnectionState.IDLE
        assert eng_manual.power_enabled is False

    def test_connect_and_complete_transitions(self) -> None:
        eng = CipSafetySpeHybridEngine(auto_activate=False)
        assert eng.state == SafetyConnectionState.IDLE

        eng.connect()
        assert eng.state == SafetyConnectionState.CONNECTING
        assert eng.power_enabled is False

        eng.complete_connection()
        assert eng.state == SafetyConnectionState.RUNNING
        assert eng.power_enabled is True
        assert eng.is_healthy is True

    def test_disconnect(self) -> None:
        eng = CipSafetySpeHybridEngine(auto_activate=True)
        assert eng.state == SafetyConnectionState.RUNNING
        eng.disconnect()
        assert eng.state == SafetyConnectionState.IDLE
        assert eng.power_enabled is False

    def test_watchdog_timeout_transition(self) -> None:
        eng = CipSafetySpeHybridEngine(auto_activate=True, watchdog_timeout_ms=100.0)
        eng.scan_step(dt_ms=50.0)
        assert eng.state == SafetyConnectionState.RUNNING
        eng.scan_step(dt_ms=60.0)  # Total 110ms > 100ms
        assert eng.state == SafetyConnectionState.FAULT
        assert eng.diagnostic_code == DIAG_ERR_TIMEOUT
        assert eng.power_enabled is False
        assert eng.is_tripped is True

    def test_feed_heartbeat_and_feed_watchdog_alias(self) -> None:
        eng = CipSafetySpeHybridEngine(auto_activate=True, watchdog_timeout_ms=100.0)
        eng.scan_step(dt_ms=80.0)
        assert eng.state == SafetyConnectionState.RUNNING
        eng.feed_heartbeat()
        assert eng.time_since_last_heartbeat_ms == 0.0
        eng.scan_step(dt_ms=80.0)
        assert eng.state == SafetyConnectionState.RUNNING
        eng.feed_watchdog()
        assert eng.time_since_last_heartbeat_ms == 0.0

    def test_manual_trip_transitions_to_fault_state(self) -> None:
        eng = CipSafetySpeHybridEngine(auto_activate=True)
        eng.trip_fail_safe(DIAG_ERR_GROUND_LEAKAGE)
        assert eng.state == SafetyConnectionState.FAULT
        assert eng.diagnostic_code == DIAG_ERR_GROUND_LEAKAGE
        assert eng.is_tripped is True
        assert eng.error_count == 1


# ============================================================================
# 6. TestUnderVoltageAndOverCurrentTrips
# ============================================================================

class TestUnderVoltageAndOverCurrentTrips:
    """Validate bus voltage and current physical trip limits and safe de-energization."""

    def test_under_voltage_trip_and_recovery(self) -> None:
        eng = CipSafetySpeHybridEngine()
        assert eng.is_healthy is True

        eng.inject_under_voltage(17000)
        assert eng.voltage_mv == 17000
        assert eng.diagnostic_code == DIAG_ERR_UNDER_VOLTAGE
        assert eng.state == SafetyConnectionState.FAULT
        assert eng.power_enabled is False
        assert eng.is_tripped is True
        assert (eng.status_word & int(CipSafetySpeHybridStatusBits.UNDER_VOLTAGE)) != 0

        eng.clear_faults()
        assert eng.voltage_mv == 24000
        assert eng.diagnostic_code == DIAG_OK
        assert eng.is_healthy is True
        assert eng.power_enabled is True

    def test_over_current_trip_and_timing(self) -> None:
        eng = CipSafetySpeHybridEngine()
        eng.inject_over_current(1950)
        assert eng.current_ma == 1950
        assert eng.diagnostic_code == DIAG_ERR_OVER_CURRENT
        assert eng.state == SafetyConnectionState.FAULT
        assert eng.power_enabled is False
        assert eng.is_tripped is True
        assert eng.last_fault_deenergize_time_ms < 5.0
        assert (eng.status_word & int(CipSafetySpeHybridStatusBits.OVER_CURRENT)) != 0

        eng.clear_faults()
        assert eng.current_ma == 500
        assert eng.is_healthy is True

    def test_voltage_clamping_and_deenergization(self) -> None:
        eng = CipSafetySpeHybridEngine()
        eng.inject_under_voltage(12000)
        assert eng.power_enabled is False
        assert eng.power_mw == 0  # Unpowered returns 0 mW
        assert (eng.status_word & int(CipSafetySpeHybridStatusBits.POWER_ENABLE)) == 0


# ============================================================================
# 7. TestHighLoopResistanceAndGroundLeakageTrips
# ============================================================================

class TestHighLoopResistanceAndGroundLeakageTrips:
    """Validate loop resistance (> 65.0 Ohm) and ground leakage (> 5.0 mA) monitoring."""

    def test_high_loop_resistance_trip(self) -> None:
        eng = CipSafetySpeHybridEngine()
        eng.inject_high_loop_resistance(70000)
        assert eng.loop_resistance_mohm == 70000
        assert eng.diagnostic_code == DIAG_ERR_HIGH_LOOP_RESISTANCE
        assert eng.state == SafetyConnectionState.FAULT
        assert eng.power_enabled is False
        assert (eng.status_word & int(CipSafetySpeHybridStatusBits.HIGH_LOOP_RESISTANCE)) != 0

        eng.clear_faults()
        assert eng.loop_resistance_mohm == 2000
        assert eng.is_healthy is True

    def test_ground_leakage_trip(self) -> None:
        eng = CipSafetySpeHybridEngine()
        eng.inject_ground_leakage(7.5)
        assert eng.ground_leakage_ma == 7.5
        assert eng.diagnostic_code == DIAG_ERR_GROUND_LEAKAGE
        assert eng.state == SafetyConnectionState.FAULT
        assert (eng.status_word & int(CipSafetySpeHybridStatusBits.GROUND_LEAKAGE)) != 0

        eng.clear_faults()
        assert eng.ground_leakage_ma == 0.0
        assert eng.is_healthy is True

    def test_safe_deenergization_timing_under_5ms(self) -> None:
        eng = CipSafetySpeHybridEngine()
        eng.trip_fail_safe(DIAG_ERR_OVER_CURRENT)
        assert eng.last_fault_deenergize_time_ms < 5.0

    def test_inject_timeout_trip(self) -> None:
        eng = CipSafetySpeHybridEngine()
        eng.inject_timeout()
        assert eng.diagnostic_code == DIAG_ERR_TIMEOUT
        assert eng.state == SafetyConnectionState.FAULT
        assert (eng.status_word & int(CipSafetySpeHybridStatusBits.TIMEOUT)) != 0


# ============================================================================
# 8. TestFrameTransmissionAndReception
# ============================================================================

class TestFrameTransmissionAndReception:
    """Validate safety frame exchange, sequence counters, dual CRC validation, and error interception."""

    def test_send_safety_frame(self) -> None:
        eng = CipSafetySpeHybridEngine()
        f1 = eng.send_safety_frame(payload=b"\x01\x02")
        assert f1.sequence_number == 0
        assert f1.validate_crcs() is True
        assert eng.sequence_counter == 1

        f2 = eng.send_safety_frame(payload=b"\x03\x04")
        assert f2.sequence_number == 1
        assert eng.sequence_counter == 2

    def test_receive_valid_frame(self) -> None:
        tx_eng = CipSafetySpeHybridEngine()
        rx_eng = CipSafetySpeHybridEngine()

        frame = tx_eng.send_safety_frame(payload=b"\xAA\xBB\xCC\xDD")
        assert rx_eng.receive_safety_frame(frame) is True
        assert rx_eng.time_since_last_heartbeat_ms == 0.0
        assert rx_eng.last_rx_frame == frame

    def test_receive_corrupted_crc_s1(self) -> None:
        tx_eng = CipSafetySpeHybridEngine()
        rx_eng = CipSafetySpeHybridEngine()

        frame = tx_eng.send_safety_frame(payload=b"\x11\x22\x33\x44")
        frame.mutate_crc_s1()
        assert rx_eng.receive_safety_frame(frame) is False
        assert rx_eng.state == SafetyConnectionState.FAULT
        assert rx_eng.diagnostic_code == DIAG_ERR_CRC_S1
        assert rx_eng.last_crc_s1_valid is False

    def test_receive_corrupted_crc_s2(self) -> None:
        tx_eng = CipSafetySpeHybridEngine()
        rx_eng = CipSafetySpeHybridEngine()

        frame = tx_eng.send_safety_frame(payload=b"\x11\x22\x33\x44")
        frame.mutate_crc_s2()
        assert rx_eng.receive_safety_frame(frame) is False
        assert rx_eng.state == SafetyConnectionState.FAULT
        assert rx_eng.diagnostic_code == DIAG_ERR_CRC_S2
        assert rx_eng.last_crc_s2_valid is False

    def test_receive_snn_mismatch(self) -> None:
        tx_eng = CipSafetySpeHybridEngine(safety_network_number=0x1111)
        rx_eng = CipSafetySpeHybridEngine(safety_network_number=0x2222)

        frame = tx_eng.send_safety_frame(payload=b"\x11\x22\x33\x44")
        assert rx_eng.receive_safety_frame(frame) is False
        assert rx_eng.state == SafetyConnectionState.FAULT

    def test_receive_frame_when_idle_returns_false(self) -> None:
        tx_eng = CipSafetySpeHybridEngine()
        rx_eng = CipSafetySpeHybridEngine(auto_activate=False)
        frame = tx_eng.send_safety_frame(payload=b"\x11\x22")
        assert rx_eng.receive_safety_frame(frame) is False

    def test_receive_frame_with_under_voltage(self) -> None:
        tx_eng = CipSafetySpeHybridEngine()
        rx_eng = CipSafetySpeHybridEngine()
        frame = tx_eng.send_safety_frame(payload=b"\x11\x22")
        frame.voltage_mv = 16000
        frame.compute_crcs()
        assert rx_eng.receive_safety_frame(frame) is False
        assert rx_eng.diagnostic_code == DIAG_ERR_UNDER_VOLTAGE

    def test_receive_frame_with_over_current(self) -> None:
        tx_eng = CipSafetySpeHybridEngine()
        rx_eng = CipSafetySpeHybridEngine()
        frame = tx_eng.send_safety_frame(payload=b"\x11\x22")
        frame.current_ma = 2000
        frame.compute_crcs()
        assert rx_eng.receive_safety_frame(frame) is False
        assert rx_eng.diagnostic_code == DIAG_ERR_OVER_CURRENT

    def test_receive_frame_with_high_loop_resistance(self) -> None:
        tx_eng = CipSafetySpeHybridEngine()
        rx_eng = CipSafetySpeHybridEngine()
        frame = tx_eng.send_safety_frame(payload=b"\x11\x22")
        frame.loop_resistance_mohm = 70000
        frame.compute_crcs()
        assert rx_eng.receive_safety_frame(frame) is False
        assert rx_eng.diagnostic_code == DIAG_ERR_HIGH_LOOP_RESISTANCE


# ============================================================================
# 9. TestHornerOcsRegisterSynchronization
# ============================================================================

class TestHornerOcsRegisterSynchronization:
    """Validate Horner OCS registers (%R2590..%R2597) and discrete coils (%M604..%M605)."""

    def test_nominal_registers_and_coils(self) -> None:
        rt = RegisterTable()
        eng = CipSafetySpeHybridEngine(register_table=rt)
        eng.sync_to_registers(rt, privilege=PrivilegeMode.USER)

        assert (rt.read_word(REG_CIP_SAFETY_SPE_VOLTAGE_MV) & 0xFFFF) == 24000
        assert (rt.read_word(REG_CIP_SAFETY_SPE_CURRENT_MA) & 0xFFFF) == 500
        assert (rt.read_word(REG_CIP_SAFETY_SPE_POWER_MW) & 0xFFFF) == 12000
        assert (rt.read_word(REG_CIP_SAFETY_SPE_LOOP_RESISTANCE_MOHM) & 0xFFFF) == 2000
        assert (rt.read_word(REG_CIP_SAFETY_SPE_STATUS_WORD) & 3) == 3
        assert (rt.read_word(REG_CIP_SAFETY_SPE_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
        assert (rt.read_word(REG_CIP_SAFETY_SPE_ERROR_COUNT) & 0xFFFF) == 0
        assert (rt.read_word(REG_CIP_SAFETY_SPE_SEQUENCE_COUNTER) & 0xFFFF) == 0

        assert rt.read_bit(COIL_CIP_SAFETY_SPE_POWER_ENABLE) is True
        assert rt.read_bit(COIL_CIP_SAFETY_SPE_TRIP) is False

    def test_fault_registers_and_coils(self) -> None:
        rt = RegisterTable()
        eng = CipSafetySpeHybridEngine(register_table=rt)
        eng.inject_under_voltage(15000)

        assert (rt.read_word(REG_CIP_SAFETY_SPE_VOLTAGE_MV) & 0xFFFF) == 15000
        assert (rt.read_word(REG_CIP_SAFETY_SPE_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE31
        assert (rt.read_word(REG_CIP_SAFETY_SPE_ERROR_COUNT) & 0xFFFF) == 1
        assert rt.read_bit(COIL_CIP_SAFETY_SPE_POWER_ENABLE) is False
        assert rt.read_bit(COIL_CIP_SAFETY_SPE_TRIP) is True

    def test_all_diagnostic_codes_in_register_table(self) -> None:
        codes = [
            DIAG_ERR_UNDER_VOLTAGE,
            DIAG_ERR_OVER_CURRENT,
            DIAG_ERR_HIGH_LOOP_RESISTANCE,
            DIAG_ERR_GROUND_LEAKAGE,
            DIAG_ERR_TIMEOUT,
            DIAG_ERR_CRC_S1,
            DIAG_ERR_CRC_S2,
        ]
        rt = RegisterTable()
        eng = CipSafetySpeHybridEngine(register_table=rt)
        for code in codes:
            eng.trip_fail_safe(code)
            assert (rt.read_word(REG_CIP_SAFETY_SPE_DIAGNOSTIC_CODE) & 0xFFFF) == code
            assert rt.read_bit(COIL_CIP_SAFETY_SPE_TRIP) is True
            assert rt.read_bit(COIL_CIP_SAFETY_SPE_POWER_ENABLE) is False

    def test_register_sync_sequence_counter_and_error_count(self) -> None:
        rt = RegisterTable()
        eng = CipSafetySpeHybridEngine(register_table=rt)
        eng.sequence_counter = 45000
        eng.error_count = 5
        eng.sync_to_registers(rt)
        assert (rt.read_word(REG_CIP_SAFETY_SPE_SEQUENCE_COUNTER) & 0xFFFF) == 45000
        assert (rt.read_word(REG_CIP_SAFETY_SPE_ERROR_COUNT) & 0xFFFF) == 5

    def test_register_sync_privilege_modes(self) -> None:
        rt = RegisterTable()
        eng = CipSafetySpeHybridEngine(register_table=rt)
        eng.sync_to_registers(rt, privilege=PrivilegeMode.APPLICATION)
        assert (rt.read_word(REG_CIP_SAFETY_SPE_VOLTAGE_MV) & 0xFFFF) == 24000
        eng.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert (rt.read_word(REG_CIP_SAFETY_SPE_VOLTAGE_MV) & 0xFFFF) == 24000


# ============================================================================
# 10. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface compliance (scan_step, step, execute, reset)."""

    def test_logic_unit_properties(self) -> None:
        eng = CipSafetySpeHybridEngine()
        assert isinstance(eng, ILogicUnit)
        assert eng.name == "CipSafetySpeHybridEngine"
        assert eng.priority == 10
        assert eng.is_enabled is True

    def test_scan_step_context_propagation_hierarchy(self) -> None:
        rt_local = RegisterTable()
        eng = CipSafetySpeHybridEngine()

        # Context with register_table
        class CustomContext:
            register_table = rt_local
            dt_ms = 10.0

        res = eng.scan_step(CustomContext())
        assert res.status == AgentStatus.SUCCESS
        assert (rt_local.read_word(REG_CIP_SAFETY_SPE_VOLTAGE_MV) & 0xFFFF) == 24000

    def test_step_and_execute(self) -> None:
        eng = CipSafetySpeHybridEngine()
        eng.step(dt=0.010)
        assert eng.cycles_count == 1
        res = eng.execute()
        assert res.status == AgentStatus.SUCCESS
        assert eng.cycles_count == 2

    def test_reset(self) -> None:
        eng = CipSafetySpeHybridEngine()
        eng.sequence_counter = 55
        eng.error_count = 3
        eng.cycles_count = 100
        eng.inject_under_voltage(16000)

        eng.reset()
        assert eng.sequence_counter == 0
        assert eng.error_count == 0
        assert eng.cycles_count == 0
        assert eng.is_healthy is True
        assert eng.diagnostic_code == DIAG_OK

    def test_scan_step_with_dt_args_and_kwargs(self) -> None:
        eng = CipSafetySpeHybridEngine()
        res1 = eng.scan_step(0.020)
        assert res1.status == AgentStatus.SUCCESS
        res2 = eng.scan_step(dt=0.020)
        assert res2.status == AgentStatus.SUCCESS
        res3 = eng.scan_step(dt_ms=20.0)
        assert res3.status == AgentStatus.SUCCESS
        assert eng.cycles_count == 3

    def test_scan_step_surveillance_trips(self) -> None:
        eng = CipSafetySpeHybridEngine()
        eng.voltage_mv = 16000  # Below under-voltage threshold
        res = eng.scan_step()
        assert res.status == AgentStatus.FAILED
        assert eng.diagnostic_code == DIAG_ERR_UNDER_VOLTAGE
        assert eng.state == SafetyConnectionState.FAULT


# ============================================================================
# 11. TestPureIEC61131StructuredTextAndSecurity
# ============================================================================

class TestPureIEC61131StructuredTextAndSecurity:
    """Validate Pure IEC 61131-3 ST POU syntax and rejection of forbidden ladder logic."""

    def test_pure_st_pou_syntax_and_registers(self) -> None:
        assert verify_cip_safety_spe_hybrid_pure_st() is True
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_SPE_HYBRID_SYNC)
        ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_SPE_HYBRID_SYNC)
        assert ast.pou_type == POUType.PROGRAM

        expected = {
            "%R2590", "%R2591", "%R2592", "%R2593",
            "%R2594", "%R2595", "%R2596", "%R2597",
            "%M604", "%M605",
        }
        assert expected.issubset(set(ast.bound_registers))

    def test_ladder_constructs_rejection(self) -> None:
        forbidden = [
            "PROGRAM Test VAR x : BOOL; END_VAR ---[ ]--- x; END_PROGRAM",
            "PROGRAM Test VAR x : BOOL; END_VAR ---[/]--- x; END_PROGRAM",
            "PROGRAM Test VAR y : BOOL; END_VAR ---( )--- y; END_PROGRAM",
            "PROGRAM Test VAR y : BOOL; END_VAR ---(S)--- y; END_PROGRAM",
            "PROGRAM Test VAR y : BOOL; END_VAR ---(R)--- y; END_PROGRAM",
            "PROGRAM Test RUNG 1 END_PROGRAM",
            "PROGRAM Test NETWORK 1 END_PROGRAM",
            "PROGRAM Test XIC(tag); END_PROGRAM",
            "PROGRAM Test OTE(tag); END_PROGRAM",
        ]
        for snippet in forbidden:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(snippet)

    def test_ladder_forbidden_error_on_all_ladder_elements(self) -> None:
        elements = [
            ("---[ ]---", "Normally open contact"),
            ("---[/]---", "Normally closed contact"),
            ("---( )---", "Normal coil"),
            ("---(S)---", "Set coil"),
            ("---(R)---", "Reset coil"),
            ("RUNG 1", "Rung keyword"),
            ("NETWORK 1", "Network keyword"),
            ("XIC(", "Examine if closed instruction"),
            ("OTE(", "Output energize instruction"),
        ]
        for elem, desc in elements:
            code = f"PROGRAM LTest VAR a : BOOL; END_VAR\n{elem}\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError, match=r"ERR_LADDER_FORBIDDEN"):
                SecurityGuard.assert_pure_st_content(code)


# ============================================================================
# 12. TestSoakAndMemoryStability
# ============================================================================

class TestSoakAndMemoryStability:
    """Validate 100-cycle continuous simulation scan soak stability and memory efficiency."""

    def test_100_cycle_soak(self) -> None:
        tracemalloc.start()
        eng = CipSafetySpeHybridEngine()
        snap1 = tracemalloc.take_snapshot()

        for _ in range(100):
            res = eng.scan_step(dt_ms=10.0)
            assert res.status == AgentStatus.SUCCESS
            eng.feed_watchdog()

        assert eng.cycles_count == 100
        assert eng.error_count == 0
        assert eng.is_healthy is True

        snap2 = tracemalloc.take_snapshot()
        tracemalloc.stop()
        stats = snap2.compare_to(snap1, "lineno")
        total_growth = sum(s.size_diff for s in stats if s.size_diff > 0)
        assert total_growth < 2 * 1024 * 1024


# ============================================================================
# 13. TestNineStageVerificationRunner
# ============================================================================

class TestNineStageVerificationRunner:
    """Validate complete 9-stage verification suite run_cip_safety_spe_hybrid_verification."""

    def test_run_verification_success(self) -> None:
        evidence = run_cip_safety_spe_hybrid_verification()
        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert evidence["stages_passed"] == 9
        assert evidence["total_stages"] == 9
        assert evidence["passed_stages"] == 9
        assert len(evidence["data"]["stages"]) == 9

        for stg in evidence["data"]["stages"]:
            assert stg["passed"] is True
            assert stg["timing_ms"] >= 0.0

    def test_run_verification_file_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "w298_evidence.json"
            res = run_cip_safety_spe_hybrid_verification(output_path=out_file)
            assert res["status"] == "success"
            assert out_file.exists()
            data = json.loads(out_file.read_text(encoding="utf-8"))
            assert data["status"] == "success"
            assert data["stages_passed"] == 9

    def test_run_verification_all_9_stages_individual_checks(self) -> None:
        evidence = run_cip_safety_spe_hybrid_verification()
        stage_names = [stg["name"] for stg in evidence["data"]["stages"]]
        expected_names = [
            "init_and_power_classes",
            "dual_safety_crc",
            "connection_state_machine",
            "under_voltage_trip",
            "over_current_trip",
            "high_loop_resistance_trip",
            "ground_leakage_and_timeout",
            "horner_ocs_register_sync",
            "pure_st_pou_and_ladder_rejection",
        ]
        assert stage_names == expected_names
        for stg in evidence["data"]["stages"]:
            assert stg["passed"] is True

    def test_run_verification_strict_4_state_contract(self) -> None:
        evidence = run_cip_safety_spe_hybrid_verification()
        assert evidence["status"] in ("success", "failed", "blocked", "inconclusive")
        assert "data" in evidence
        assert "details" in evidence
        assert evidence["data"]["work_package"] == "W298"
        assert evidence["data"]["gate"] == "G8"
