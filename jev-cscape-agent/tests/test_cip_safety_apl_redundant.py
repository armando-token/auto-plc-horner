"""Comprehensive Unit Test Suite for Wave W277 CIP Safety Over Ethernet-APL Redundant Trunks Protocol Engine.

Work Package: W277 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Ethernet-APL Redundant Trunks (10BASE-T1L / 2-WISE Intrinsically Safe) for Horner OCS.

Covers Comprehensive Deterministic Unit Tests across 12 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnostics: Protocol constants, nominal/IS voltage limits (9600..15000 mV),
   failover latency bounds (<2500 us), register mappings (%R2380..%R2387), coil mappings (%M555..%M556),
   CipSafetyRedundantState, ActiveTrunkId, CipSafetyRedundantDiagnosticCode, bitwise ops and repr.
2. TestDualSafetyCrcCalculation: CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B inverted data) calculations,
   determinism, distinctness, bit-flip corruption detection across all byte and bit offsets.
3. TestEngineInitializationAndDefaults: CipSafetyAplRedundantEngine defaults with and without RegisterTable,
   metadata properties (name, priority, is_enabled, is_healthy), and reset behavior.
4. TestDualTrunkVoltageSurveillance: 2-WISE intrinsically safe loop voltage surveillance (nominal 12000 mV),
   under-voltage droop (<9600 mV -> 0xEC01/0xEC02), over-voltage violation (>15000 mV), exact IS bounds,
   dual trunk failure (0xEC03 DUAL_TRUNK_FAIL), mixed voltage trips, and recovery.
5. TestFailoverAndBumplessSwitchover: Failover and bumpless switchover between Trunk A and Trunk B,
   switchover latency surveillance (<2500 us), switchover timeout trip (0xEC04 SWITCHOVER_TIMEOUT),
   and 16-bit rolling switchover counter rollover.
6. TestSplitBrainAndIntegrityFaults: Split-brain synchronization loss injection (0xEC05 SPLIT_BRAIN_SYNC_LOSS),
   sequence sync bit clearing in CRC status word, register updates, and recovery via reset.
7. TestRegisterTableSynchronization: %R2380..%R2387 and %M555..%M556 bit-exact synchronization,
   privilege mode support, readback fidelity, and coil mutual exclusivity.
8. ILogicUnit compliance: scan_step, step, execute, reset, sequence counter rollover, and 100-cycle soak.
9. TestPureStructuredTextAndSecurity: STParser AST validation of ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC,
   variable address validation (%R2380..%R2387, %M555..%M556), and verify_cip_safety_apl_redundant_pure_st.
10. TestAntiLadderConstructRejection: Rejection of ladder logic constructs (contacts, coils, rungs, networks, mnemonics)
    with LadderForbiddenError.
11. TestVerificationRunner9Stages: 9-stage verification suite run_cip_safety_apl_redundant_verification,
    strict 4-state contract validation, and JSON evidence file emission.
12. TestComplexScenariosAndStateTransitions: Chained cascade failures, recovery cycles, hysteresis,
    and multi-trunk degradation pathways.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_apl_redundant import (
    DEFAULT_DEVICE_ID,
    DEFAULT_SNN,
    NOMINAL_VOLTAGE_MV,
    MIN_IS_VOLTAGE_MV,
    MAX_IS_VOLTAGE_MV,
    NOMINAL_LATENCY_US,
    MAX_SWITCHOVER_LATENCY_US,
    CRC16_S1_POLY,
    CRC16_S2_POLY,
    CRC16_INIT,
    REG_CIP_SAFETY_REDUNDANT_STATE,
    REG_CIP_SAFETY_REDUNDANT_ACTIVE_TRUNK,
    REG_CIP_SAFETY_REDUNDANT_TRUNK_A_VOLTAGE_MV,
    REG_CIP_SAFETY_REDUNDANT_TRUNK_B_VOLTAGE_MV,
    REG_CIP_SAFETY_REDUNDANT_SWITCHOVER_COUNT,
    REG_CIP_SAFETY_REDUNDANT_CRC_STATUS,
    REG_CIP_SAFETY_REDUNDANT_LATENCY_US,
    REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE,
    COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED,
    COIL_CIP_SAFETY_REDUNDANT_TRIPPED,
    CipSafetyRedundantState,
    ActiveTrunkId,
    CipSafetyRedundantDiagnosticCode,
    compute_crc_s1,
    compute_crc_s2,
    ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC,
    CIP_SAFETY_APL_REDUNDANT_PURE_ST_POU,
    verify_cip_safety_apl_redundant_pure_st,
    CipSafetyAplRedundantEngine,
    CIPSafetyAplRedundantEngine,
    CIPSafetyAPLRedundantEngine,
    run_cip_safety_apl_redundant_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety Over Ethernet-APL Redundant Trunks constants, enums, and diagnostic codes."""

    def test_protocol_constants_and_limits(self) -> None:
        assert DEFAULT_DEVICE_ID == 0x1A2B
        assert DEFAULT_SNN == 0x9876
        assert NOMINAL_VOLTAGE_MV == 12000
        assert MIN_IS_VOLTAGE_MV == 9600
        assert MAX_IS_VOLTAGE_MV == 15000
        assert NOMINAL_LATENCY_US == 1200
        assert MAX_SWITCHOVER_LATENCY_US == 2500

    def test_crc_polynomial_constants(self) -> None:
        assert CRC16_S1_POLY == 0x5935
        assert CRC16_S2_POLY == 0x755B
        assert CRC16_INIT == 0xFFFF

    def test_register_and_coil_mappings(self) -> None:
        assert REG_CIP_SAFETY_REDUNDANT_STATE == "%R2380"
        assert REG_CIP_SAFETY_REDUNDANT_ACTIVE_TRUNK == "%R2381"
        assert REG_CIP_SAFETY_REDUNDANT_TRUNK_A_VOLTAGE_MV == "%R2382"
        assert REG_CIP_SAFETY_REDUNDANT_TRUNK_B_VOLTAGE_MV == "%R2383"
        assert REG_CIP_SAFETY_REDUNDANT_SWITCHOVER_COUNT == "%R2384"
        assert REG_CIP_SAFETY_REDUNDANT_CRC_STATUS == "%R2385"
        assert REG_CIP_SAFETY_REDUNDANT_LATENCY_US == "%R2386"
        assert REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE == "%R2387"

        assert COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED == "%M555"
        assert COIL_CIP_SAFETY_REDUNDANT_TRIPPED == "%M556"

    def test_redundant_state_enum(self) -> None:
        assert CipSafetyRedundantState.TRUNK_A_ACTIVE == 0
        assert CipSafetyRedundantState.TRUNK_B_ACTIVE == 1
        assert CipSafetyRedundantState.DUAL_TRACKING == 2
        assert CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED == 3
        assert CipSafetyRedundantState.TRIP_SHUTDOWN == 4

        # Member names
        assert CipSafetyRedundantState(0).name == "TRUNK_A_ACTIVE"
        assert CipSafetyRedundantState(1).name == "TRUNK_B_ACTIVE"
        assert CipSafetyRedundantState(2).name == "DUAL_TRACKING"
        assert CipSafetyRedundantState(3).name == "SAFETY_FALLBACK_DEGRADED"
        assert CipSafetyRedundantState(4).name == "TRIP_SHUTDOWN"

    def test_active_trunk_id_enum(self) -> None:
        assert ActiveTrunkId.TRUNK_A == 1
        assert ActiveTrunkId.TRUNK_B == 2
        assert ActiveTrunkId.BOTH_SYNCHRONIZED == 3

        assert ActiveTrunkId(1).name == "TRUNK_A"
        assert ActiveTrunkId(2).name == "TRUNK_B"
        assert ActiveTrunkId(3).name == "BOTH_SYNCHRONIZED"

    def test_diagnostic_code_enum_values(self) -> None:
        assert CipSafetyRedundantDiagnosticCode.OK == 0x0000
        assert CipSafetyRedundantDiagnosticCode.TRUNK_A_DROOP == 0xEC01
        assert CipSafetyRedundantDiagnosticCode.TRUNK_B_DROOP == 0xEC02
        assert CipSafetyRedundantDiagnosticCode.DUAL_TRUNK_FAIL == 0xEC03
        assert CipSafetyRedundantDiagnosticCode.SWITCHOVER_TIMEOUT == 0xEC04
        assert CipSafetyRedundantDiagnosticCode.SPLIT_BRAIN_SYNC_LOSS == 0xEC05

    def test_diagnostic_code_bitwise_and_formatting(self) -> None:
        code = CipSafetyRedundantDiagnosticCode.TRUNK_A_DROOP
        assert (code & 0xFFFF) == 0xEC01
        assert (code | 0x0010) == 0xEC11
        assert (code ^ 0x0001) == 0xEC00
        assert f"0x{code.value:04X}" == "0xEC01"
        assert hash(code) == hash(0xEC01)
        assert int(code) == 0xEC01

    def test_class_aliases(self) -> None:
        assert CIPSafetyAplRedundantEngine is CipSafetyAplRedundantEngine
        assert CIPSafetyAPLRedundantEngine is CipSafetyAplRedundantEngine
        assert CIP_SAFETY_APL_REDUNDANT_PURE_ST_POU == ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC


# ============================================================================
# 2. TestDualSafetyCrcCalculation
# ============================================================================

class TestDualSafetyCrcCalculation:
    """Validate dual Safety CRC calculation (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B inverted data)."""

    def test_crc_s1_computation_determinism(self) -> None:
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        crc1_first = compute_crc_s1(data)
        crc1_second = compute_crc_s1(data)
        assert crc1_first == crc1_second
        assert isinstance(crc1_first, int)
        assert 0 <= crc1_first <= 0xFFFF

    def test_crc_s2_computation_determinism(self) -> None:
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        crc2_first = compute_crc_s2(data)
        crc2_second = compute_crc_s2(data)
        assert crc2_first == crc2_second
        assert isinstance(crc2_first, int)
        assert 0 <= crc2_first <= 0xFFFF

    def test_crc_s1_and_crc_s2_distinct_polynomials(self) -> None:
        payloads = [
            b"CIP_SAFETY_FRAME_PAYLOAD_10BASE_T1L",
            b"\xAA\x55\xAA\x55\x00\xFF",
            b"\x00" * 16,
            b"\xFF" * 16,
            b"ODVA_IEC_61784_3_2_SIL3_REDUNDANT",
        ]
        for p in payloads:
            crc1 = compute_crc_s1(p)
            crc2 = compute_crc_s2(p)
            assert crc1 != crc2, f"CRC-S1 and CRC-S2 collided on payload: {p!r}"

    def test_crc_empty_payload(self) -> None:
        crc1_empty = compute_crc_s1(b"")
        crc2_empty = compute_crc_s2(b"")
        assert crc1_empty == 0xFFFF
        assert crc2_empty == 0xFFFF

    def test_single_bit_flip_detection_s1(self) -> None:
        base_data = bytearray(b"\x12\x34\x56\x78\x9A\xBC\xDE\xF0")
        base_crc = compute_crc_s1(bytes(base_data))

        # Corrupt every single bit across all 8 bytes
        for byte_idx in range(len(base_data)):
            for bit_idx in range(8):
                corrupted = bytearray(base_data)
                corrupted[byte_idx] ^= (1 << bit_idx)
                corrupted_crc = compute_crc_s1(bytes(corrupted))
                assert corrupted_crc != base_crc, (
                    f"CRC-S1 failed to detect bitflip at byte {byte_idx}, bit {bit_idx}"
                )

    def test_single_bit_flip_detection_s2(self) -> None:
        base_data = bytearray(b"\x12\x34\x56\x78\x9A\xBC\xDE\xF0")
        base_crc = compute_crc_s2(bytes(base_data))

        # Corrupt every single bit across all 8 bytes
        for byte_idx in range(len(base_data)):
            for bit_idx in range(8):
                corrupted = bytearray(base_data)
                corrupted[byte_idx] ^= (1 << bit_idx)
                corrupted_crc = compute_crc_s2(bytes(corrupted))
                assert corrupted_crc != base_crc, (
                    f"CRC-S2 failed to detect bitflip at byte {byte_idx}, bit {bit_idx}"
                )

    def test_multi_bit_corruption_detection(self) -> None:
        data = b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
        crc1 = compute_crc_s1(data)
        crc2 = compute_crc_s2(data)

        inverted = bytes(~b & 0xFF for b in data)
        assert compute_crc_s1(inverted) != crc1
        assert compute_crc_s2(inverted) != crc2


# ============================================================================
# 3. TestEngineInitializationAndDefaults
# ============================================================================

class TestEngineInitializationAndDefaults:
    """Validate engine initialization defaults, properties, and reset behavior."""

    def test_engine_defaults_without_registers(self) -> None:
        engine = CipSafetyAplRedundantEngine()
        assert engine.register_table is None
        assert engine.state == CipSafetyRedundantState.DUAL_TRACKING
        assert engine.active_trunk == ActiveTrunkId.BOTH_SYNCHRONIZED
        assert engine.trunk_a_voltage_mv == NOMINAL_VOLTAGE_MV
        assert engine.trunk_b_voltage_mv == NOMINAL_VOLTAGE_MV
        assert engine.switchover_count == 0
        assert engine.crc_status == 0x0007
        assert engine.latency_us == NOMINAL_LATENCY_US
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.OK
        assert engine.tx_sequence == 0
        assert engine.rx_sequence == 0
        assert engine.cycles_count == 0
        assert engine.is_healthy is True

    def test_engine_defaults_with_register_table(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)
        assert engine.register_table is rt
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_STATE) == 2
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_ACTIVE_TRUNK) == 3
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_TRUNK_A_VOLTAGE_MV) == 12000
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_TRUNK_B_VOLTAGE_MV) == 12000
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_SWITCHOVER_COUNT) == 0
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_CRC_STATUS) == 0x0007
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_LATENCY_US) == 1200
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE) == 0x0000
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED) is True
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is False

    def test_engine_properties_metadata(self) -> None:
        engine = CipSafetyAplRedundantEngine()
        assert engine.name == "CipSafetyAplRedundantEngine"
        assert engine.priority == 10
        assert engine.is_enabled is True
        assert engine.is_healthy is True

    def test_engine_reset_restores_nominal_state(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        # Force degraded state and non-zero sequences
        engine.state = CipSafetyRedundantState.TRIP_SHUTDOWN
        engine.active_trunk = ActiveTrunkId.TRUNK_A
        engine.trunk_a_voltage_mv = 5000
        engine.trunk_b_voltage_mv = 4000
        engine.switchover_count = 42
        engine.crc_status = 0x0000
        engine.latency_us = 9999
        engine.diagnostic_code = CipSafetyRedundantDiagnosticCode.DUAL_TRUNK_FAIL
        engine.tx_sequence = 1234
        engine.rx_sequence = 5678
        engine.cycles_count = 100
        engine.sync_to_registers(rt)

        assert engine.is_healthy is False
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is True

        # Perform reset
        engine.reset()

        assert engine.state == CipSafetyRedundantState.DUAL_TRACKING
        assert engine.active_trunk == ActiveTrunkId.BOTH_SYNCHRONIZED
        assert engine.trunk_a_voltage_mv == 12000
        assert engine.trunk_b_voltage_mv == 12000
        assert engine.switchover_count == 0
        assert engine.crc_status == 0x0007
        assert engine.latency_us == 1200
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.OK
        assert engine.tx_sequence == 0
        assert engine.rx_sequence == 0
        assert engine.cycles_count == 0
        assert engine.is_healthy is True

        # Verify registers restored bit-for-bit
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_STATE) == 2
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_ACTIVE_TRUNK) == 3
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_TRUNK_A_VOLTAGE_MV) == 12000
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_TRUNK_B_VOLTAGE_MV) == 12000
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_SWITCHOVER_COUNT) == 0
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_CRC_STATUS) == 0x0007
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_LATENCY_US) == 1200
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE) == 0x0000
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED) is True
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is False


# ============================================================================
# 4. TestDualTrunkVoltageSurveillance
# ============================================================================

class TestDualTrunkVoltageSurveillance:
    """Validate 2-WISE dual-trunk loop voltage surveillance (nominal 12000 mV, IS bounds 9600..15000 mV)."""

    def test_nominal_voltage_operation(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)
        healthy = engine.monitor_voltages(12000, 12000)
        assert healthy is True
        assert engine.state == CipSafetyRedundantState.DUAL_TRACKING
        assert engine.active_trunk == ActiveTrunkId.BOTH_SYNCHRONIZED
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.OK
        assert (engine.crc_status & 0x0003) == 0x0003
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED) is True
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is False

    def test_voltage_boundary_conditions(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        # Minimum IS voltage (9600 mV)
        assert engine.monitor_voltages(9600, 9600) is True
        assert engine.is_healthy is True
        assert engine.state == CipSafetyRedundantState.DUAL_TRACKING

        # Maximum IS voltage (15000 mV)
        assert engine.monitor_voltages(15000, 15000) is True
        assert engine.is_healthy is True
        assert engine.state == CipSafetyRedundantState.DUAL_TRACKING

        # Cross bounds (min on Trunk A, max on Trunk B)
        assert engine.monitor_voltages(9600, 15000) is True
        assert engine.is_healthy is True
        assert engine.state == CipSafetyRedundantState.DUAL_TRACKING

    def test_trunk_a_undervoltage_droop(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        # 9599 mV is just below MIN_IS_VOLTAGE_MV (9600 mV)
        healthy = engine.monitor_voltages(9599, 12000)
        assert healthy is False
        assert engine.state == CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED
        assert engine.active_trunk == ActiveTrunkId.TRUNK_B
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.TRUNK_A_DROOP
        assert (engine.crc_status & 0x0001) == 0
        assert (engine.crc_status & 0x0002) != 0
        assert engine.switchover_count == 1
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_STATE) == 3
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE) == 0xEC01
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED) is False
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is True

    def test_trunk_a_overvoltage_violation(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        # 15001 mV exceeds MAX_IS_VOLTAGE_MV (15000 mV)
        healthy = engine.monitor_voltages(15001, 12000)
        assert healthy is False
        assert engine.state == CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED
        assert engine.active_trunk == ActiveTrunkId.TRUNK_B
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.TRUNK_A_DROOP
        assert engine.switchover_count == 1

    def test_trunk_b_undervoltage_droop(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        healthy = engine.monitor_voltages(12000, 9599)
        assert healthy is False
        assert engine.state == CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED
        assert engine.active_trunk == ActiveTrunkId.TRUNK_A
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.TRUNK_B_DROOP
        assert (engine.crc_status & 0x0001) != 0
        assert (engine.crc_status & 0x0002) == 0
        assert engine.switchover_count == 1
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_STATE) == 3
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE) == 0xEC02
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED) is False
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is True

    def test_trunk_b_overvoltage_violation(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        healthy = engine.monitor_voltages(12000, 16000)
        assert healthy is False
        assert engine.state == CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED
        assert engine.active_trunk == ActiveTrunkId.TRUNK_A
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.TRUNK_B_DROOP
        assert engine.switchover_count == 1

    def test_dual_trunk_undervoltage_trip(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        healthy = engine.monitor_voltages(8000, 8000)
        assert healthy is False
        assert engine.state == CipSafetyRedundantState.TRIP_SHUTDOWN
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.DUAL_TRUNK_FAIL
        assert (engine.crc_status & 0x0003) == 0
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_STATE) == 4
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE) == 0xEC03
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED) is False
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is True

    def test_dual_trunk_overvoltage_trip(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        healthy = engine.monitor_voltages(16000, 17000)
        assert healthy is False
        assert engine.state == CipSafetyRedundantState.TRIP_SHUTDOWN
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.DUAL_TRUNK_FAIL
        assert (engine.crc_status & 0x0003) == 0

    def test_mixed_voltage_fault_trip(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        # Trunk A undervoltage, Trunk B overvoltage
        healthy = engine.monitor_voltages(5000, 18000)
        assert healthy is False
        assert engine.state == CipSafetyRedundantState.TRIP_SHUTDOWN
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.DUAL_TRUNK_FAIL

    def test_recovery_from_voltage_trip(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        # Fault condition
        engine.monitor_voltages(8000, 8000)
        assert engine.state == CipSafetyRedundantState.TRIP_SHUTDOWN

        # Recover voltages back to nominal 12000 mV
        healthy = engine.monitor_voltages(12000, 12000)
        assert healthy is True
        assert engine.state == CipSafetyRedundantState.DUAL_TRACKING
        assert engine.active_trunk == ActiveTrunkId.BOTH_SYNCHRONIZED
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.OK
        assert (engine.crc_status & 0x0003) == 0x0003
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED) is True
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is False


# ============================================================================
# 5. TestFailoverAndBumplessSwitchover
# ============================================================================

class TestFailoverAndBumplessSwitchover:
    """Validate bumpless switchover, failover latency bounds, and counter rollover."""

    def test_nominal_switchover_to_trunk_a(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        ok = engine.switchover_to_trunk(ActiveTrunkId.TRUNK_A, switchover_time_us=1200)
        assert ok is True
        assert engine.state == CipSafetyRedundantState.TRUNK_A_ACTIVE
        assert engine.active_trunk == ActiveTrunkId.TRUNK_A
        assert engine.latency_us == 1200
        assert engine.switchover_count == 1
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_STATE) == 0
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_ACTIVE_TRUNK) == 1
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_SWITCHOVER_COUNT) == 1

    def test_nominal_switchover_to_trunk_b(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        ok = engine.switchover_to_trunk(ActiveTrunkId.TRUNK_B, switchover_time_us=1500)
        assert ok is True
        assert engine.state == CipSafetyRedundantState.TRUNK_B_ACTIVE
        assert engine.active_trunk == ActiveTrunkId.TRUNK_B
        assert engine.latency_us == 1500
        assert engine.switchover_count == 1
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_STATE) == 1
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_ACTIVE_TRUNK) == 2

    def test_switchover_to_dual_tracking(self) -> None:
        engine = CipSafetyAplRedundantEngine()
        engine.switchover_to_trunk(ActiveTrunkId.TRUNK_A)
        assert engine.state == CipSafetyRedundantState.TRUNK_A_ACTIVE

        engine.switchover_to_trunk(ActiveTrunkId.BOTH_SYNCHRONIZED)
        assert engine.state == CipSafetyRedundantState.DUAL_TRACKING
        assert engine.active_trunk == ActiveTrunkId.BOTH_SYNCHRONIZED
        assert engine.switchover_count == 2

    def test_switchover_counter_increment(self) -> None:
        engine = CipSafetyAplRedundantEngine()
        assert engine.switchover_count == 0

        for i in range(1, 11):
            target = ActiveTrunkId.TRUNK_B if i % 2 == 1 else ActiveTrunkId.TRUNK_A
            engine.switchover_to_trunk(target)
            assert engine.switchover_count == i

    def test_switchover_counter_16bit_rollover(self) -> None:
        engine = CipSafetyAplRedundantEngine()
        engine.switchover_count = 0xFFFF  # 65535

        ok = engine.switchover_to_trunk(ActiveTrunkId.TRUNK_A, switchover_time_us=1000)
        assert ok is True
        assert engine.switchover_count == 0  # Rolled over to 0

    def test_switchover_boundary_latency(self) -> None:
        engine = CipSafetyAplRedundantEngine()

        # Exact threshold 2500 us is permitted
        ok = engine.switchover_to_trunk(ActiveTrunkId.TRUNK_B, switchover_time_us=2500)
        assert ok is True
        assert engine.state == CipSafetyRedundantState.TRUNK_B_ACTIVE
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.OK

    def test_switchover_timeout_trip(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        # 2501 us violates MAX_SWITCHOVER_LATENCY_US
        ok = engine.switchover_to_trunk(ActiveTrunkId.TRUNK_A, switchover_time_us=2501)
        assert ok is False
        assert engine.state == CipSafetyRedundantState.TRIP_SHUTDOWN
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.SWITCHOVER_TIMEOUT
        assert engine.latency_us == 2501
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_STATE) == 4
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE) == 0xEC04
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED) is False
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is True


# ============================================================================
# 6. TestSplitBrainAndIntegrityFaults
# ============================================================================

class TestSplitBrainAndIntegrityFaults:
    """Validate split-brain sync loss, sequence synchronization bit clearance, and recovery."""

    def test_split_brain_sync_loss_injection(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)
        assert engine.is_healthy is True

        engine.inject_split_brain_sync_loss()
        assert engine.is_healthy is False
        assert engine.state == CipSafetyRedundantState.TRIP_SHUTDOWN
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.SPLIT_BRAIN_SYNC_LOSS
        assert (engine.crc_status & 0x0004) == 0

        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_STATE) == 4
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE) == 0xEC05
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED) is False
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is True

    def test_split_brain_clears_crc_status_seq_bit(self) -> None:
        engine = CipSafetyAplRedundantEngine()
        assert engine.crc_status == 0x0007  # Bit0=1, Bit1=1, Bit2=1

        engine.inject_split_brain_sync_loss()
        assert engine.crc_status == 0x0003  # Bit2 cleared, Bit0 & Bit1 intact

    def test_split_brain_recovery_via_reset(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)
        engine.inject_split_brain_sync_loss()
        assert engine.state == CipSafetyRedundantState.TRIP_SHUTDOWN

        engine.reset()
        assert engine.state == CipSafetyRedundantState.DUAL_TRACKING
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.OK
        assert engine.crc_status == 0x0007
        assert engine.is_healthy is True
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED) is True
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is False

    def test_crc_status_bitmask_transitions(self) -> None:
        engine = CipSafetyAplRedundantEngine()
        assert engine.crc_status == 0x0007

        # Droop Trunk A: bit 0 cleared, bit 1 set
        engine.monitor_voltages(8000, 12000)
        assert (engine.crc_status & 0x0001) == 0
        assert (engine.crc_status & 0x0002) == 0x0002

        # Droop Trunk B: bit 1 cleared, bit 0 set
        engine.monitor_voltages(12000, 8000)
        assert (engine.crc_status & 0x0001) == 0x0001
        assert (engine.crc_status & 0x0002) == 0

        # Dual fail: both bits 0 and 1 cleared
        engine.monitor_voltages(8000, 8000)
        assert (engine.crc_status & 0x0003) == 0


# ============================================================================
# 7. TestRegisterTableSynchronization
# ============================================================================

class TestRegisterTableSynchronization:
    """Validate %R2380..%R2387 and %M555..%M556 bit-exact synchronization."""

    def test_nominal_sync_all_registers(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(
            register_table=rt,
            state=CipSafetyRedundantState.DUAL_TRACKING,
            active_trunk=ActiveTrunkId.BOTH_SYNCHRONIZED,
            trunk_a_voltage_mv=12345,
            trunk_b_voltage_mv=12456,
            switchover_count=7,
            crc_status=0x0007,
            latency_us=1100,
            diagnostic_code=CipSafetyRedundantDiagnosticCode.OK,
        )

        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_STATE) == 2
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_ACTIVE_TRUNK) == 3
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_TRUNK_A_VOLTAGE_MV) == 12345
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_TRUNK_B_VOLTAGE_MV) == 12456
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_SWITCHOVER_COUNT) == 7
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_CRC_STATUS) == 0x0007
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_LATENCY_US) == 1100
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE) == 0x0000

        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED) is True
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is False

    def test_tripped_sync_all_registers(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)
        engine.state = CipSafetyRedundantState.TRIP_SHUTDOWN
        engine.active_trunk = ActiveTrunkId.TRUNK_A
        engine.trunk_a_voltage_mv = 7500
        engine.trunk_b_voltage_mv = 7600
        engine.switchover_count = 15
        engine.crc_status = 0x0000
        engine.latency_us = 3500
        engine.diagnostic_code = CipSafetyRedundantDiagnosticCode.DUAL_TRUNK_FAIL
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_STATE) == 4
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_ACTIVE_TRUNK) == 1
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_TRUNK_A_VOLTAGE_MV) == 7500
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_TRUNK_B_VOLTAGE_MV) == 7600
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_SWITCHOVER_COUNT) == 15
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_CRC_STATUS) == 0x0000
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_LATENCY_US) == 3500
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE) == 0xEC03

        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED) is False
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is True

    def test_privilege_modes(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine()
        # System privilege should write successfully
        engine.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_STATE) == 2

    def test_coil_truth_table_consistency(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        # In all operational / degraded / tripped states, coils must be strictly opposite
        states_to_test = [
            (12000, 12000, True),   # DUAL_TRACKING -> established=True, tripped=False
            (8000, 12000, False),   # TRUNK_A_DROOP -> established=False, tripped=True
            (12000, 8000, False),   # TRUNK_B_DROOP -> established=False, tripped=True
            (8000, 8000, False),    # DUAL_TRUNK_FAIL -> established=False, tripped=True
        ]
        for va, vb, expected_healthy in states_to_test:
            engine.monitor_voltages(va, vb)
            est = rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED)
            trp = rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED)
            assert est is expected_healthy
            assert trp is (not expected_healthy)
            assert est != trp, "Coils %M555 and %M556 cannot have identical values"


# ============================================================================
# 8. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit protocol compliance (scan_step, step, execute, reset)."""

    def test_interface_inheritance(self) -> None:
        engine = CipSafetyAplRedundantEngine()
        assert isinstance(engine, ILogicUnit)

    def test_scan_step_cycles_and_sequences(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)
        assert engine.cycles_count == 0
        assert engine.tx_sequence == 0
        assert engine.rx_sequence == 0

        engine.scan_step(0.01)
        assert engine.cycles_count == 1
        assert engine.tx_sequence == 1
        assert engine.rx_sequence == 1

        engine.scan_step(0.01)
        assert engine.cycles_count == 2
        assert engine.tx_sequence == 2
        assert engine.rx_sequence == 2

    def test_step_alias_method(self) -> None:
        engine = CipSafetyAplRedundantEngine()
        engine.step(0.02)
        assert engine.cycles_count == 1
        assert engine.tx_sequence == 1
        assert engine.rx_sequence == 1

    def test_sequence_counter_16bit_rollover(self) -> None:
        engine = CipSafetyAplRedundantEngine()
        engine.tx_sequence = 0xFFFF
        engine.rx_sequence = 0xFFFF

        engine.scan_step(0.01)
        assert engine.tx_sequence == 0
        assert engine.rx_sequence == 0

    def test_execute_healthy_status(self) -> None:
        engine = CipSafetyAplRedundantEngine()
        res: ExecutionResult = engine.execute()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.data["state"] == "DUAL_TRACKING"
        assert res.data["active_trunk"] == "BOTH_SYNCHRONIZED"
        assert res.data["diagnostic_code"] == "0x0000"
        assert res.data["switchover_count"] == 0

    def test_execute_tripped_status(self) -> None:
        engine = CipSafetyAplRedundantEngine()
        engine.monitor_voltages(5000, 5000)
        res: ExecutionResult = engine.execute()
        assert res.status == AgentStatus.FAILED
        assert res.data["state"] == "TRIP_SHUTDOWN"
        assert res.data["diagnostic_code"] == "0xEC03"

    def test_multi_scan_cycle_soak(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)
        context = ScanContext(cycle=0, dt_ms=10.0)

        for cycle in range(100):
            context.cycle = cycle
            engine.scan_step(0.01, context)

        assert engine.cycles_count == 100
        assert engine.tx_sequence == 100
        assert engine.rx_sequence == 100
        assert engine.is_healthy is True
        assert rt.read_word(REG_CIP_SAFETY_REDUNDANT_STATE) == 2


# ============================================================================
# 9. TestPureStructuredTextAndSecurity
# ============================================================================

class TestPureStructuredTextAndSecurity:
    """Validate IEC 61131-3 Pure Structured Text POU parsing, AST, and security assertions."""

    def test_pure_st_pou_string_constants(self) -> None:
        assert isinstance(ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC, str)
        assert len(ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC) > 100
        assert "PROGRAM ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC" in ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC
        assert "END_PROGRAM" in ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC

    def test_st_parser_ast_program_type(self) -> None:
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse(ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC"
        assert len(ast.variables) == 11

    def test_st_parser_bound_registers(self) -> None:
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse(ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC)
        expected_registers = [
            "%R2380",
            "%R2381",
            "%R2382",
            "%R2383",
            "%R2384",
            "%R2385",
            "%R2386",
            "%R2387",
            "%M555",
            "%M556",
        ]
        assert ast.bound_registers == expected_registers

    def test_st_parser_variable_names_and_types(self) -> None:
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse(ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC)
        var_names = [v.name for v in ast.variables]
        assert "RedundantState" in var_names
        assert "ActiveTrunk" in var_names
        assert "TrunkAVoltageMv" in var_names
        assert "TrunkBVoltageMv" in var_names
        assert "SwitchoverCount" in var_names
        assert "CrcStatus" in var_names
        assert "FailoverLatencyUs" in var_names
        assert "DiagnosticCode" in var_names
        assert "LinkEstablished" in var_names
        assert "LinkTripped" in var_names
        assert "InternalHealthy" in var_names

    def test_verify_cip_safety_apl_redundant_pure_st_default(self) -> None:
        assert verify_cip_safety_apl_redundant_pure_st() is True

    def test_verify_cip_safety_apl_redundant_pure_st_custom_valid(self) -> None:
        valid_pou = """PROGRAM ValidCustomSync
VAR
    State AT %R2380 : INT;
    Trip AT %M556 : BOOL;
END_VAR
IF State > 3 THEN
    Trip := TRUE;
END_IF;
END_PROGRAM
"""
        assert verify_cip_safety_apl_redundant_pure_st(valid_pou) is True

    def test_verify_cip_safety_apl_redundant_pure_st_invalid_syntax(self) -> None:
        invalid_pou = "THIS IS NOT STRUCTURED TEXT AND CONTAINS SYNTAX CRASH @@$$"
        assert verify_cip_safety_apl_redundant_pure_st(invalid_pou) is False

    def test_security_guard_assert_pure_st(self) -> None:
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_APL_REDUNDANT_SYNC)


# ============================================================================
# 10. TestAntiLadderConstructRejection
# ============================================================================

class TestAntiLadderConstructRejection:
    """Validate strict rejection of ladder logic contacts, coils, rungs, and mnemonics."""

    def test_reject_ladder_normally_open_contact(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR x: BOOL; END_VAR ---[ ]--- END_PROGRAM")

    def test_reject_ladder_normally_closed_contact(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR x: BOOL; END_VAR ---[/]--- END_PROGRAM")

    def test_reject_ladder_output_coil(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR x: BOOL; END_VAR ---( )--- END_PROGRAM")

    def test_reject_ladder_set_reset_coils(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR x: BOOL; END_VAR ---(S)--- END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P VAR x: BOOL; END_VAR ---(R)--- END_PROGRAM")

    def test_reject_ladder_rung_delimiters(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P RUNG 1: X := 1; END_PROGRAM")

    def test_reject_ladder_network_delimiters(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P NETWORK 10: X := 1; END_PROGRAM")

    def test_reject_ladder_mnemonics(self) -> None:
        mnemonics = ["XIC", "XIO", "OTE", "OTL", "OTU"]
        for m in mnemonics:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(f"PROGRAM P {m} InputBit; END_PROGRAM")

    def test_verify_pure_st_function_rejects_ladder(self) -> None:
        ladder_code = """PROGRAM LadderTest
VAR
    InPin AT %I001 : BOOL;
    OutPin AT %Q001 : BOOL;
END_VAR
---[ ]---( )---
END_PROGRAM
"""
        assert verify_cip_safety_apl_redundant_pure_st(ladder_code) is False


# ============================================================================
# 11. TestVerificationRunner9Stages
# ============================================================================

class TestVerificationRunner9Stages:
    """Validate 9-stage verification suite run_cip_safety_apl_redundant_verification."""

    def test_runner_all_9_stages_pass(self) -> None:
        res = run_cip_safety_apl_redundant_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["work_package"] == "W277"
        assert res["data"]["gate"] == "G8"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9

    def test_runner_stage_structure_and_schema(self) -> None:
        res = run_cip_safety_apl_redundant_verification()
        stages = res["data"]["stages"]
        assert len(stages) == 9

        expected_stage_names = [
            "enums_and_constants",
            "dual_safety_crc_calculation",
            "pure_st_anti_ladder_guard",
            "nominal_dual_tracking",
            "trunk_a_droop_failover",
            "trunk_b_droop_failover",
            "dual_trunk_trip_shutdown",
            "switchover_timeout_detection",
            "split_brain_sync_loss_and_scan",
        ]

        for idx, (stage, expected_name) in enumerate(zip(stages, expected_stage_names), start=1):
            assert stage["stage"] == idx
            assert stage["name"] == expected_name
            assert stage["passed"] is True

    def test_runner_strict_4_state_contract(self) -> None:
        res = run_cip_safety_apl_redundant_verification()
        assert res["status"] in ("success", "failed", "blocked", "inconclusive")
        assert "details" in res
        assert isinstance(res["details"], str)
        assert "9/9" in res["details"]

    def test_runner_file_output_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "evidence" / "cip_safety_apl_redundant_evidence.json"
            res = run_cip_safety_apl_redundant_verification(output_path=out_file)

            assert out_file.exists()
            assert out_file.stat().st_size > 0

            with open(out_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)

            assert loaded["status"] == "success"
            assert loaded["data"]["work_package"] == "W277"
            assert loaded["data"]["checks_passed"] == 9


# ============================================================================
# 12. TestComplexScenariosAndStateTransitions
# ============================================================================

class TestComplexScenariosAndStateTransitions:
    """Validate complex operational transitions, chained cascade faults, and hysteresis."""

    def test_cascade_failure_sequence(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        # 1. Start healthy dual tracking
        assert engine.state == CipSafetyRedundantState.DUAL_TRACKING
        assert engine.active_trunk == ActiveTrunkId.BOTH_SYNCHRONIZED

        # 2. Trunk A droops -> Failover to Trunk B
        engine.monitor_voltages(8500, 12000)
        assert engine.state == CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED
        assert engine.active_trunk == ActiveTrunkId.TRUNK_B
        assert engine.switchover_count == 1

        # 3. Trunk B subsequently droops -> Complete shutdown
        engine.monitor_voltages(8500, 8000)
        assert engine.state == CipSafetyRedundantState.TRIP_SHUTDOWN
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.DUAL_TRUNK_FAIL
        assert (engine.crc_status & 0x0003) == 0

        # 4. Trunk B recovers, Trunk A still bad -> Fallback to Trunk B
        engine.monitor_voltages(8500, 12000)
        assert engine.state == CipSafetyRedundantState.SAFETY_FALLBACK_DEGRADED
        assert engine.active_trunk == ActiveTrunkId.TRUNK_B

        # 5. Trunk A recovers -> Both synchronized
        engine.monitor_voltages(12000, 12000)
        assert engine.state == CipSafetyRedundantState.DUAL_TRACKING
        assert engine.active_trunk == ActiveTrunkId.BOTH_SYNCHRONIZED
        assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.OK

    def test_rapid_alternating_trunk_droops(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)

        # Oscillate between Trunk A down and Trunk B down
        for i in range(5):
            # Trunk A droop -> switches to Trunk B
            engine.monitor_voltages(8000, 12000)
            assert engine.active_trunk == ActiveTrunkId.TRUNK_B
            assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.TRUNK_A_DROOP

            # Trunk B droop -> switches to Trunk A
            engine.monitor_voltages(12000, 8000)
            assert engine.active_trunk == ActiveTrunkId.TRUNK_A
            assert engine.diagnostic_code == CipSafetyRedundantDiagnosticCode.TRUNK_B_DROOP

        assert engine.switchover_count == 10
        assert rt.read_uword(REG_CIP_SAFETY_REDUNDANT_SWITCHOVER_COUNT) == 10

    def test_execute_tripped_details_payload(self) -> None:
        engine = CipSafetyAplRedundantEngine()
        engine.switchover_to_trunk(ActiveTrunkId.TRUNK_B, switchover_time_us=3200)  # Timeout trip

        res = engine.execute()
        assert res.status == AgentStatus.FAILED
        assert res.data["state"] == "TRIP_SHUTDOWN"
        assert res.data["active_trunk"] == "TRUNK_B"
        assert res.data["diagnostic_code"] == "0xEC04"
        assert res.data["switchover_count"] == 1

    def test_scan_step_preserves_fault_state(self) -> None:
        rt = RegisterTable()
        engine = CipSafetyAplRedundantEngine(register_table=rt)
        engine.monitor_voltages(8000, 8000)
        assert engine.state == CipSafetyRedundantState.TRIP_SHUTDOWN

        # Run 10 scan steps during trip
        for _ in range(10):
            engine.scan_step(0.01)

        assert engine.state == CipSafetyRedundantState.TRIP_SHUTDOWN
        assert engine.cycles_count == 10
        assert engine.tx_sequence == 10
        assert rt.read_bit(COIL_CIP_SAFETY_REDUNDANT_TRIPPED) is True
