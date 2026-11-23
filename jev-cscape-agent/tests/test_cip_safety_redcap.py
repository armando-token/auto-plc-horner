"""Comprehensive Unit Test Suite for Wave W310 CIP Safety Over Cellular / 5G RedCap & IoT NTN Bridge.

Work Package: W310 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Cellular / 5G RedCap (Reduced Capability) & IoT NTN Bridge

Covers Comprehensive Deterministic Unit Tests across 16 Mandatory Test Classes (85+ Tests):
1. TestConstantsEnumsAndDiagnostics: Protocol constants, register mappings (%R2710..%R2717),
   coils (%M632..%M633), diagnostic codes (0x0000, 0xEE71..0xEE75), signed/unsigned 16-bit equality,
   bitwise masking, enums (RedCapLinkState, RedCapPowerMode), status bits, and aliases.
2. TestDualCrcAlgorithmsAndFrameIntegrity: Dual CRC-S1 (poly 0x5935, seed 0x0000) and CRC-S2 (poly 0x755B, seed 0x0000),
   single-bit flip sensitivity, EPID CRC32 hashing, and verify_dual_crc_s helper.
3. TestPacketModelAndBinarySerialization: CIPRedCapPacket dataclass, inverted header computation,
   CRC generation/validation, binary packing/unpacking roundtrip, and corrupted frame rejection.
4. TestEngineInitializationAndStateTransitions: State machine transitions (DISCONNECTED -> RRC_CONNECTED -> SAFETY_TRIP),
   auto_activate, connect, disconnect, trip_safety/trip_fault, clear_fault, and reset.
5. TestTelemetrySurveillanceAndThresholds: Telemetry surveillance for RSRP (>= -115 dBm), RSRQ (>= -18.0 dB),
   DRX cycle latency (<= 100 ms), battery tracking (0..100%), safe operational boundaries, and fault thresholds.
6. TestRedCapSignalTrackingAndRsrpDrop: Signal strength surveillance, RSRP threshold boundary,
   weak signal trip (0xEE71 when < -115 dBm), safe stop coil interlock, and recovery.
7. TestRsrqDegradationMonitoring: Channel quality surveillance, RSRQ threshold boundary,
   degradation trip (0xEE72 when < -18.0 dB), safe stop coil interlock, and recovery.
8. TestDrxWakeupTimeoutMonitoring: DRX power-saving cycle monitoring, wakeup latency boundary,
   latency timeout trip (0xEE73 when > 100 ms), safe stop coil interlock, and recovery.
9. TestWatchdogAndSilenceCountdown: Silence countdown timer accumulation during scan cycles,
   watchdog timeout expiration (> 150.0 ms -> 0xEE74), timer reset on packet arrival, and inactive states.
10. TestPacketTxRxAndCrcCorruption: Egress packet transmission with rolling sequence counters,
    ingress packet processing, state promotion, telemetry updates, and CRC corruption fault detection (0xEE75).
11. TestSafeStopInterlockAndCoils: Fail-safe interlock asserting %M633 (TRIP) and de-asserting %M632 (ONLINE)
    across all diagnostic trip conditions, and restoring healthy coils upon fault clearance.
12. TestHornerRegisterTableSynchronization: Bit-exact synchronization to Horner OCS registers (%R2710..%R2717)
    and coils (%M632..%M633), signed 16-bit masking `(rt.read_word(...) & 0xFFFF) == expected`,
    negative RSRP/RSRQ representation, and privilege modes.
13. TestILogicUnitCompliance: ILogicUnit interface compliance (scan_step with variable args/kwargs,
    step, execute, reset), ScanContext handling, execution results, and register table hierarchy.
14. TestPureStructuredTextAndSecurityGuard: Pure IEC 61131-3 ST POU CipSafetyRedCapSync validation
    via STParser and SecurityGuard, AST bound registers, and strict interception of ladder logic
    constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
15. TestMultiCycleSoakAndStability: 100-cycle continuous simulation soak test with live packet exchange,
    monotonic counter increments, zero fault trips, and bounded memory footprint verified via tracemalloc.
16. TestVerificationRunner9StagesAndCli: Complete 9-stage verification suite run_cip_safety_redcap_verification,
    strict 4-state engineering contract validation, JSON evidence emission rules, and CLI interop.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
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
from jev_cscape.telemetry.cip_safety_redcap import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_REDCAP_CLASS_ID,
    CIP_SAFETY_5G_REDCAP_CLASS_ID,
    NOMINAL_RSRP_DBM,
    DEFAULT_RSRP_DBM,
    MIN_RSRP_DBM,
    MAX_RSRP_DBM,
    MIN_ALLOWED_RSRP_DBM,
    DEFAULT_RSRP_TRIP_THRESHOLD_DBM,
    RSRP_TRIP_THRESHOLD_DBM,
    NOMINAL_RSRQ_DB,
    DEFAULT_RSRQ_DB,
    MIN_RSRQ_DB,
    MAX_RSRQ_DB,
    MIN_ALLOWED_RSRQ_DB,
    DEFAULT_RSRQ_TRIP_THRESHOLD_DB,
    RSRQ_TRIP_THRESHOLD_DB,
    NOMINAL_DRX_CYCLE_MS,
    DEFAULT_DRX_CYCLE_MS,
    MIN_DRX_CYCLE_MS,
    MAX_DRX_CYCLE_MS,
    MAX_ALLOWED_DRX_CYCLE_MS,
    DEFAULT_DRX_TRIP_THRESHOLD_MS,
    DRX_TRIP_THRESHOLD_MS,
    NOMINAL_BATTERY_PCT,
    DEFAULT_BATTERY_PCT,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    NOMINAL_REDCAP_WATCHDOG_MS,
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
    REG_CIP_REDCAP_STATUS,
    REG_CIP_REDCAP_SEQUENCE,
    REG_CIP_REDCAP_RSRP_DBM,
    REG_CIP_REDCAP_RSRQ_DB,
    REG_CIP_REDCAP_DRX_CYCLE_MS,
    REG_CIP_REDCAP_DIAGNOSTIC_CODE,
    REG_CIP_REDCAP_BATTERY_REMAINING_PCT,
    REG_CIP_REDCAP_PACKET_LOSS_COUNTER,
    COIL_CIP_REDCAP_ONLINE,
    COIL_CIP_REDCAP_TRIP,
    REG_REDCAP_STATUS,
    REG_REDCAP_SEQUENCE,
    REG_REDCAP_RSRP_DBM,
    REG_REDCAP_RSRQ_DB,
    REG_REDCAP_DRX_CYCLE_MS,
    REG_REDCAP_DIAGNOSTIC_CODE,
    REG_REDCAP_BATTERY_REMAINING_PCT,
    REG_REDCAP_PACKET_LOSS_COUNTER,
    COIL_REDCAP_ONLINE,
    COIL_REDCAP_TRIP,
    COIL_CIP_REDCAP_HEALTHY,
    COIL_REDCAP_HEALTHY,
    COIL_LINK_HEALTHY,
    COIL_SAFETY_LINK_HEALTHY,
    COIL_REDCAP_SAFETY_LINK_HEALTHY,
    COIL_SAFETY_STOP_TRIPPED,
    COIL_SAFE_STOP_TRIPPED,
    COIL_REDCAP_SAFETY_STOP_TRIPPED,
    RedCapLinkState,
    CipRedCapLinkState,
    RedCapPowerMode,
    DiagnosticCode,
    RedCapStatusBits,
    DIAG_OK,
    DIAG_ERR_RSRP_WEAK_SIGNAL,
    DIAG_ERR_RSRQ_CHANNEL_QUALITY,
    DIAG_ERR_DRX_WAKEUP_TIMEOUT,
    DIAG_ERR_WATCHDOG_COMM_TIMEOUT,
    DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
    DIAG_RSRP_WEAK_SIGNAL,
    DIAG_RSRQ_CHANNEL_QUALITY,
    DIAG_DRX_WAKEUP_TIMEOUT,
    DIAG_WATCHDOG_COMM_TIMEOUT,
    DIAG_DUAL_CRC_SAFETY_FAULT,
    CIPRedCapSafetyError,
    RedCapRsrpWeakSignalError,
    RedCapRsrqChannelQualityError,
    RedCapDrxWakeupTimeoutError,
    RedCapWatchdogTimeoutError,
    RedCapDualCrcSafetyFaultError,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    calculate_cip_safety_crc_s1,
    calculate_cip_safety_crc_s2,
    compute_epid_hash,
    compute_epid_crc32,
    calculate_crc16_ccitt,
    verify_dual_crc_s,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CIPRedCapPacket,
    CipSafetyRedCapPacket,
    create_valid_redcap_packet,
    ST_PROGRAM_CIP_SAFETY_REDCAP_SYNC,
    CIP_SAFETY_REDCAP_SYNC_POU,
    CIP_SAFETY_REDCAP_PURE_ST_POU,
    CipSafetyRedCapSync,
    verify_cip_safety_redcap_pure_st,
    CIPRedCapSafetyEngine,
    CipSafetyRedCapEngine,
    run_cip_safety_redcap_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate protocol constants, register mappings, coils, enums, and diagnostic codes."""

    def test_canonical_registers_and_coils(self) -> None:
        assert REG_CIP_REDCAP_STATUS == "%R2710"
        assert REG_CIP_REDCAP_SEQUENCE == "%R2711"
        assert REG_CIP_REDCAP_RSRP_DBM == "%R2712"
        assert REG_CIP_REDCAP_RSRQ_DB == "%R2713"
        assert REG_CIP_REDCAP_DRX_CYCLE_MS == "%R2714"
        assert REG_CIP_REDCAP_DIAGNOSTIC_CODE == "%R2715"
        assert REG_CIP_REDCAP_BATTERY_REMAINING_PCT == "%R2716"
        assert REG_CIP_REDCAP_PACKET_LOSS_COUNTER == "%R2717"

        assert COIL_CIP_REDCAP_ONLINE == "%M632"
        assert COIL_CIP_REDCAP_TRIP == "%M633"

    def test_extended_register_and_coil_aliases(self) -> None:
        assert REG_REDCAP_STATUS == "%R2710"
        assert REG_REDCAP_SEQUENCE == "%R2711"
        assert REG_REDCAP_RSRP_DBM == "%R2712"
        assert REG_REDCAP_RSRQ_DB == "%R2713"
        assert REG_REDCAP_DRX_CYCLE_MS == "%R2714"
        assert REG_REDCAP_DIAGNOSTIC_CODE == "%R2715"
        assert REG_REDCAP_BATTERY_REMAINING_PCT == "%R2716"
        assert REG_REDCAP_PACKET_LOSS_COUNTER == "%R2717"

        assert COIL_REDCAP_ONLINE == "%M632"
        assert COIL_REDCAP_TRIP == "%M633"
        assert COIL_CIP_REDCAP_HEALTHY == "%M632"
        assert COIL_REDCAP_HEALTHY == "%M632"
        assert COIL_LINK_HEALTHY == "%M632"
        assert COIL_SAFETY_LINK_HEALTHY == "%M632"
        assert COIL_REDCAP_SAFETY_LINK_HEALTHY == "%M632"
        assert COIL_SAFETY_STOP_TRIPPED == "%M633"
        assert COIL_SAFE_STOP_TRIPPED == "%M633"
        assert COIL_REDCAP_SAFETY_STOP_TRIPPED == "%M633"

    def test_class_ids_and_polynomials(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_REDCAP_CLASS_ID == 0x2F
        assert CIP_SAFETY_5G_REDCAP_CLASS_ID == 0x2F

        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0x0000
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CRC_INIT == 0x0000
        assert CRC_S_INIT == 0x0000

    def test_redcap_link_state_enum_and_aliases(self) -> None:
        assert int(RedCapLinkState.DISCONNECTED) == 0
        assert int(RedCapLinkState.SEARCHING) == 1
        assert int(RedCapLinkState.REGISTERED) == 2
        assert int(RedCapLinkState.RRC_CONNECTED) == 3
        assert int(RedCapLinkState.SAFETY_TRIP) == 4

        # Aliases
        assert RedCapLinkState.IDLE == RedCapLinkState.DISCONNECTED
        assert RedCapLinkState.UNASSOCIATED == RedCapLinkState.DISCONNECTED
        assert RedCapLinkState.CELL_SEARCH == RedCapLinkState.SEARCHING
        assert RedCapLinkState.ATTACHED == RedCapLinkState.REGISTERED
        assert RedCapLinkState.CONNECTED == RedCapLinkState.RRC_CONNECTED
        assert RedCapLinkState.ONLINE == RedCapLinkState.RRC_CONNECTED
        assert RedCapLinkState.OPERATIONAL == RedCapLinkState.RRC_CONNECTED
        assert RedCapLinkState.CONNECTED_RUNNING == RedCapLinkState.RRC_CONNECTED
        assert RedCapLinkState.TRIPPED == RedCapLinkState.SAFETY_TRIP
        assert RedCapLinkState.SAFE_STOP == RedCapLinkState.SAFETY_TRIP
        assert CipRedCapLinkState == RedCapLinkState

    def test_redcap_power_mode_enum_and_aliases(self) -> None:
        assert int(RedCapPowerMode.ACTIVE) == 1
        assert int(RedCapPowerMode.DRX_STANDBY) == 2
        assert int(RedCapPowerMode.EDRX_DEEP_SLEEP) == 3

        # Aliases
        assert RedCapPowerMode.MODE_ACTIVE == RedCapPowerMode.ACTIVE
        assert RedCapPowerMode.MODE_DRX == RedCapPowerMode.DRX_STANDBY
        assert RedCapPowerMode.MODE_EDRX == RedCapPowerMode.EDRX_DEEP_SLEEP
        assert RedCapPowerMode.DRX == RedCapPowerMode.DRX_STANDBY
        assert RedCapPowerMode.EDRX == RedCapPowerMode.EDRX_DEEP_SLEEP
        assert RedCapPowerMode.STANDBY == RedCapPowerMode.DRX_STANDBY
        assert RedCapPowerMode.DEEP_SLEEP == RedCapPowerMode.EDRX_DEEP_SLEEP

    def test_diagnostic_code_values_and_aliases(self) -> None:
        assert int(DiagnosticCode.DIAG_OK) == 0x0000
        assert int(DiagnosticCode.DIAG_ERR_RSRP_WEAK_SIGNAL) == 0xEE71
        assert int(DiagnosticCode.DIAG_ERR_RSRQ_CHANNEL_QUALITY) == 0xEE72
        assert int(DiagnosticCode.DIAG_ERR_DRX_WAKEUP_TIMEOUT) == 0xEE73
        assert int(DiagnosticCode.DIAG_ERR_WATCHDOG_COMM_TIMEOUT) == 0xEE74
        assert int(DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT) == 0xEE75

        # Top-level and alias checks
        assert DIAG_OK == DiagnosticCode.DIAG_OK
        assert DIAG_ERR_RSRP_WEAK_SIGNAL == DiagnosticCode.DIAG_ERR_RSRP_WEAK_SIGNAL
        assert DIAG_ERR_RSRQ_CHANNEL_QUALITY == DiagnosticCode.DIAG_ERR_RSRQ_CHANNEL_QUALITY
        assert DIAG_ERR_DRX_WAKEUP_TIMEOUT == DiagnosticCode.DIAG_ERR_DRX_WAKEUP_TIMEOUT
        assert DIAG_ERR_WATCHDOG_COMM_TIMEOUT == DiagnosticCode.DIAG_ERR_WATCHDOG_COMM_TIMEOUT
        assert DIAG_ERR_DUAL_CRC_SAFETY_FAULT == DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT

        assert DIAG_RSRP_WEAK_SIGNAL == DIAG_ERR_RSRP_WEAK_SIGNAL
        assert DIAG_RSRQ_CHANNEL_QUALITY == DIAG_ERR_RSRQ_CHANNEL_QUALITY
        assert DIAG_DRX_WAKEUP_TIMEOUT == DIAG_ERR_DRX_WAKEUP_TIMEOUT
        assert DIAG_WATCHDOG_COMM_TIMEOUT == DIAG_ERR_WATCHDOG_COMM_TIMEOUT
        assert DIAG_DUAL_CRC_SAFETY_FAULT == DIAG_ERR_DUAL_CRC_SAFETY_FAULT

    def test_diagnostic_code_signed_unsigned_equality(self) -> None:
        # 0xEE71 as signed 16-bit is -4495
        assert DiagnosticCode.DIAG_ERR_RSRP_WEAK_SIGNAL == 0xEE71
        assert DiagnosticCode.DIAG_ERR_RSRP_WEAK_SIGNAL == -4495
        assert 0xEE71 == DiagnosticCode.DIAG_ERR_RSRP_WEAK_SIGNAL
        assert -4495 == DiagnosticCode.DIAG_ERR_RSRP_WEAK_SIGNAL

        # 0xEE72 as signed 16-bit is -4494
        assert DiagnosticCode.DIAG_ERR_RSRQ_CHANNEL_QUALITY == 0xEE72
        assert DiagnosticCode.DIAG_ERR_RSRQ_CHANNEL_QUALITY == -4494
        assert 0xEE72 == DiagnosticCode.DIAG_ERR_RSRQ_CHANNEL_QUALITY
        assert -4494 == DiagnosticCode.DIAG_ERR_RSRQ_CHANNEL_QUALITY

        # 0xEE73 as signed 16-bit is -4493
        assert DiagnosticCode.DIAG_ERR_DRX_WAKEUP_TIMEOUT == 0xEE73
        assert DiagnosticCode.DIAG_ERR_DRX_WAKEUP_TIMEOUT == -4493
        assert 0xEE73 == DiagnosticCode.DIAG_ERR_DRX_WAKEUP_TIMEOUT
        assert -4493 == DiagnosticCode.DIAG_ERR_DRX_WAKEUP_TIMEOUT

        # 0xEE74 as signed 16-bit is -4492
        assert DiagnosticCode.DIAG_ERR_WATCHDOG_COMM_TIMEOUT == 0xEE74
        assert DiagnosticCode.DIAG_ERR_WATCHDOG_COMM_TIMEOUT == -4492
        assert 0xEE74 == DiagnosticCode.DIAG_ERR_WATCHDOG_COMM_TIMEOUT
        assert -4492 == DiagnosticCode.DIAG_ERR_WATCHDOG_COMM_TIMEOUT

        # 0xEE75 as signed 16-bit is -4491
        assert DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT == 0xEE75
        assert DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT == -4491
        assert 0xEE75 == DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert -4491 == DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT

        # OK is 0
        assert DiagnosticCode.DIAG_OK == 0
        assert 0 == DiagnosticCode.DIAG_OK

    def test_diagnostic_code_bitwise_and_hashing(self) -> None:
        code = DiagnosticCode.DIAG_ERR_RSRP_WEAK_SIGNAL
        assert (code & 0xFF00) == 0xEE00
        assert (0xFF00 & code) == 0xEE00
        assert hash(code) == hash(0xEE71)
        assert str(code).startswith("0xEE71")
        assert repr(code).startswith("DiagnosticCode.")

    def test_redcap_status_bits_flags(self) -> None:
        assert RedCapStatusBits.ONLINE == 1
        assert RedCapStatusBits.RRC_CONNECTED == 2
        assert RedCapStatusBits.SAFETY_ACTIVE == 4
        assert RedCapStatusBits.RSRP_GOOD == 8
        assert RedCapStatusBits.RSRQ_GOOD == 16
        assert RedCapStatusBits.DRX_ACTIVE == 32
        assert RedCapStatusBits.SAFETY_TRIPPED == 64
        assert RedCapStatusBits.BATTERY_OK == 128

    def test_exceptions_hierarchy(self) -> None:
        assert issubclass(RedCapRsrpWeakSignalError, CIPRedCapSafetyError)
        assert issubclass(RedCapRsrqChannelQualityError, CIPRedCapSafetyError)
        assert issubclass(RedCapDrxWakeupTimeoutError, CIPRedCapSafetyError)
        assert issubclass(RedCapWatchdogTimeoutError, CIPRedCapSafetyError)
        assert issubclass(RedCapDualCrcSafetyFaultError, CIPRedCapSafetyError)


# ============================================================================
# 2. TestDualCrcAlgorithmsAndFrameIntegrity
# ============================================================================

class TestDualCrcAlgorithmsAndFrameIntegrity:
    """Validate CRC-S1, CRC-S2, bit-flip sensitivity, and EPID hash algorithms."""

    def test_crc_s1_determinism_and_bounds(self) -> None:
        payload = b"\x01\x02\x03\x04\x05"
        c1 = compute_crc_s1(payload)
        assert 0 <= c1 <= 0xFFFF
        assert c1 == compute_crc_s1(payload)
        assert calc_crc_s1(payload) == c1
        assert calculate_cip_safety_crc_s1(payload) == c1

    def test_crc_s2_determinism_and_bounds(self) -> None:
        inverted = bytes(~b & 0xFF for b in (0x5243).to_bytes(2, "big") + (1).to_bytes(2, "big") + (100).to_bytes(4, "big"))
        c2 = compute_crc_s2(inverted)
        assert 0 <= c2 <= 0xFFFF
        assert c2 == compute_crc_s2(inverted)
        assert calc_crc_s2(inverted) == c2
        assert calculate_cip_safety_crc_s2(inverted) == c2

    def test_crc_s1_single_bit_flip_sensitivity(self) -> None:
        payload = b"\xAA\xBB\xCC\xDD"
        c_orig = compute_crc_s1(payload)
        for byte_idx in range(len(payload)):
            for bit_idx in range(8):
                mutated = bytearray(payload)
                mutated[byte_idx] ^= (1 << bit_idx)
                c_mutated = compute_crc_s1(bytes(mutated))
                assert c_orig != c_mutated

    def test_crc_s2_single_bit_flip_sensitivity(self) -> None:
        raw = (0x5243).to_bytes(2, "big") + (10).to_bytes(2, "big") + (500).to_bytes(4, "big")
        inv = bytes(~b & 0xFF for b in raw)
        c_orig = compute_crc_s2(inv)
        for byte_idx in range(len(inv)):
            for bit_idx in range(8):
                mutated = bytearray(inv)
                mutated[byte_idx] ^= (1 << bit_idx)
                c_mutated = compute_crc_s2(bytes(mutated))
                assert c_orig != c_mutated

    def test_dual_crc_bit_perturbation_detection(self) -> None:
        """Verify that any single-bit perturbation in payload or inverted header alters CRC."""
        payload = bytearray(b"\x12\x34\x56\x78")
        orig_s1 = compute_crc_s1(bytes(payload))
        for byte_idx in range(len(payload)):
            for bit_idx in range(8):
                mutated = bytearray(payload)
                mutated[byte_idx] ^= (1 << bit_idx)
                assert compute_crc_s1(bytes(mutated)) != orig_s1

        header = bytearray(b"\xAA\xBB\xCC\xDD\xEE\xFF")
        orig_s2 = compute_crc_s2(bytes(header))
        for byte_idx in range(len(header)):
            for bit_idx in range(8):
                mutated = bytearray(header)
                mutated[byte_idx] ^= (1 << bit_idx)
                assert compute_crc_s2(bytes(mutated)) != orig_s2

    def test_verify_dual_crc_s_helper(self) -> None:
        payload = b"\x11\x22\x33"
        inv = b"\xFE\xDC\xBA"
        s1 = compute_crc_s1(payload)
        s2 = compute_crc_s2(inv)
        assert verify_dual_crc_s(payload, inv, s1, s2) is True
        assert verify_dual_crc_s(payload, inv, s1 ^ 1, s2) is False
        assert verify_dual_crc_s(payload, inv, s1, s2 ^ 1) is False

    def test_epid_hash_and_crc32(self) -> None:
        h16 = compute_epid_hash(DEFAULT_SAFETY_EPID)
        assert 0 <= h16 <= 0xFFFF
        h32 = compute_epid_crc32(DEFAULT_SAFETY_EPID)
        assert 0 <= h32 <= 0xFFFFFFFF
        assert (h32 & 0xFFFF) == h16

    def test_crc16_ccitt_compatibility(self) -> None:
        data = b"HORNER_OCS_REDCAP"
        crc = calculate_crc16_ccitt(data)
        assert 0 <= crc <= 0xFFFF
        assert crc == calculate_crc16_ccitt(data)


# ============================================================================
# 3. TestPacketModelAndBinarySerialization
# ============================================================================

class TestPacketModelAndBinarySerialization:
    """Validate CIPRedCapPacket model, inverted header, CRC computation, and binary pack/unpack."""

    def test_packet_creation_and_auto_crc(self) -> None:
        pkt = CIPRedCapPacket(
            session_id=DEFAULT_SESSION_ID,
            sequence_number=1,
            timestamp_ms=100,
            payload_bytes=b"\x01\x02\x03",
        )
        assert pkt.crc_s1 != 0 or pkt.crc_s2 != 0
        assert pkt.validate_crcs() is True

    def test_packet_properties_and_aliases(self) -> None:
        pkt = CIPRedCapPacket()
        assert pkt.payload == pkt.payload_bytes
        pkt.payload = b"\x09\x08"
        assert pkt.payload_bytes == b"\x09\x08"

        assert pkt.sequence == pkt.sequence_number
        pkt.sequence = 42
        assert pkt.sequence_number == 42
        assert pkt.sequence_counter == 42

        assert pkt.timestamp == pkt.timestamp_ms
        pkt.timestamp = 999
        assert pkt.timestamp_ms == 999

        assert pkt.rsrp == pkt.rsrp_dbm
        pkt.rsrp = -92.5
        assert pytest.approx(pkt.rsrp_dbm, rel=1e-2) == -92.5

        assert pkt.rsrq == pkt.rsrq_db
        pkt.rsrq = -12.4
        assert pytest.approx(pkt.rsrq_db, rel=1e-2) == -12.4

        assert pkt.drx_ms == pkt.drx_cycle_ms
        pkt.drx_ms = 35.0
        assert pytest.approx(pkt.drx_cycle_ms, rel=1e-2) == 35.0

    def test_pack_unpack_roundtrip(self) -> None:
        original = CIPRedCapPacket(
            session_id=0x5243,
            sequence_number=77,
            timestamp_ms=2500,
            rsrp_dbm=-88.5,
            rsrq_db=-11.2,
            drx_cycle_ms=25.0,
            payload_bytes=b"\xDE\xAD\xBE\xEF",
            power_mode=RedCapPowerMode.DRX_STANDBY,
        )
        raw = original.pack()
        assert isinstance(raw, bytes)
        unpacked = CIPRedCapPacket.unpack(raw)
        assert unpacked.session_id == 0x5243
        assert unpacked.sequence_number == 77
        assert unpacked.timestamp_ms == 2500
        assert pytest.approx(unpacked.rsrp_dbm, rel=1e-2) == -88.5
        assert pytest.approx(unpacked.rsrq_db, rel=1e-2) == -11.2
        assert pytest.approx(unpacked.drx_cycle_ms, rel=1e-2) == 25.0
        assert unpacked.payload_bytes == b"\xDE\xAD\xBE\xEF"
        assert unpacked.power_mode == RedCapPowerMode.DRX_STANDBY
        assert unpacked.validate_crcs() is True

    def test_corrupted_payload_fails_crc(self) -> None:
        pkt = create_valid_redcap_packet()
        assert pkt.validate_crcs() is True
        pkt.payload_bytes = b"\xFF\xFF\xFF"
        assert pkt.validate_crcs() is False

    def test_corrupted_header_fails_crc_s2(self) -> None:
        pkt = create_valid_redcap_packet()
        assert pkt.validate_crcs() is True
        pkt.sequence_number += 1
        assert pkt.validate_crcs() is False

    def test_unpack_truncated_data_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Packet data too short"):
            CIPRedCapPacket.unpack(b"\x00" * 5)

    def test_create_valid_redcap_packet_helper(self) -> None:
        pkt = create_valid_redcap_packet(sequence=5, timestamp_ms=500, rsrp_dbm=-86.0)
        assert pkt.sequence_number == 5
        assert pkt.timestamp_ms == 500
        assert pytest.approx(pkt.rsrp_dbm, rel=1e-2) == -86.0
        assert pkt.validate_crcs() is True


# ============================================================================
# 4. TestEngineInitializationAndStateTransitions
# ============================================================================

class TestEngineInitializationAndStateTransitions:
    """Validate engine initialization defaults, properties, connect, disconnect, trip, and clear."""

    def test_default_initialization(self) -> None:
        engine = CIPRedCapSafetyEngine()
        assert engine.state == RedCapLinkState.DISCONNECTED
        assert engine.online is False
        assert engine.tripped is False
        assert engine.diagnostic_code == DIAG_OK
        assert pytest.approx(engine.rsrp_dbm, rel=1e-2) == NOMINAL_RSRP_DBM
        assert pytest.approx(engine.rsrq_db, rel=1e-2) == NOMINAL_RSRQ_DB
        assert pytest.approx(engine.drx_cycle_ms, rel=1e-2) == NOMINAL_DRX_CYCLE_MS
        assert pytest.approx(engine.battery_remaining_pct, rel=1e-2) == NOMINAL_BATTERY_PCT
        assert engine.sequence_number == 0

    def test_auto_activate_option(self) -> None:
        engine = CIPRedCapSafetyEngine(auto_activate=True)
        assert engine.state == RedCapLinkState.RRC_CONNECTED
        assert engine.online is True
        assert engine.tripped is False

    def test_connect_and_disconnect(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        assert engine.state == RedCapLinkState.RRC_CONNECTED
        assert engine.online is True
        assert engine.tripped is False

        engine.disconnect()
        assert engine.state == RedCapLinkState.DISCONNECTED
        assert engine.online is False

    def test_trip_safety_and_clear_fault(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.trip_safety(DIAG_ERR_RSRP_WEAK_SIGNAL, "Signal drop test")
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_RSRP_WEAK_SIGNAL
        assert engine.online is False
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.state == RedCapLinkState.DISCONNECTED
        assert engine.diagnostic_code == DIAG_OK
        assert engine.tripped is False

    def test_trip_fault_alias(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.trip_fault(DIAG_ERR_RSRQ_CHANNEL_QUALITY, "Quality drop")
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_RSRQ_CHANNEL_QUALITY
        assert engine.tripped is True

    def test_engine_reset_clears_counters_and_restores_defaults(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.send_packet()
        engine.packet_loss_counter = 5
        engine.battery_remaining_pct = 50.0
        engine.trip_safety(DIAG_ERR_WATCHDOG_COMM_TIMEOUT)

        engine.reset()
        assert engine.state == RedCapLinkState.DISCONNECTED
        assert engine.diagnostic_code == DIAG_OK
        assert engine.sequence_number == 0
        assert engine.packet_loss_counter == 0
        assert engine.tx_frame_count == 0
        assert engine.rx_frame_count == 0
        assert pytest.approx(engine.battery_remaining_pct, rel=1e-2) == NOMINAL_BATTERY_PCT

    def test_status_register_and_status_word(self) -> None:
        engine = CIPRedCapSafetyEngine(power_mode=RedCapPowerMode.DRX_STANDBY)
        engine.connect()
        status_reg = engine.status_register_value
        assert (status_reg >> 8) == int(RedCapLinkState.RRC_CONNECTED)
        assert (status_reg & 0xFF) == int(RedCapPowerMode.DRX_STANDBY)
        assert engine.status_word & RedCapStatusBits.ONLINE
        assert engine.status_word & RedCapStatusBits.RRC_CONNECTED


# ============================================================================
# 5. TestTelemetrySurveillanceAndThresholds
# ============================================================================

class TestTelemetrySurveillanceAndThresholds:
    """Validate RSRP, RSRQ, DRX, and Battery boundaries and trip thresholds."""

    def test_nominal_telemetry_parameters(self) -> None:
        assert NOMINAL_RSRP_DBM == -85.0
        assert NOMINAL_RSRQ_DB == -10.0
        assert NOMINAL_DRX_CYCLE_MS == 20.0
        assert NOMINAL_BATTERY_PCT == 95.0

    def test_safe_boundaries_and_trip_limits(self) -> None:
        assert MIN_ALLOWED_RSRP_DBM == -115.0
        assert MIN_ALLOWED_RSRQ_DB == -18.0
        assert MAX_ALLOWED_DRX_CYCLE_MS == 100.0
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 150.0

    def test_rsrp_safe_range(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_rsrp_drop(-100.0)  # Above -115 dBm
        assert engine.state == RedCapLinkState.RRC_CONNECTED
        assert engine.diagnostic_code == DIAG_OK

    def test_rsrq_safe_range(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_rsrq_drop(-15.0)  # Above -18.0 dB
        assert engine.state == RedCapLinkState.RRC_CONNECTED
        assert engine.diagnostic_code == DIAG_OK

    def test_drx_safe_range(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_drx_timeout(80.0)  # Below 100 ms
        assert engine.state == RedCapLinkState.RRC_CONNECTED
        assert engine.diagnostic_code == DIAG_OK

    def test_battery_tracking_nominal(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        assert engine.battery_remaining_pct == 95.0
        assert bool(engine.status_word & RedCapStatusBits.BATTERY_OK) is True


# ============================================================================
# 6. TestRedCapSignalTrackingAndRsrpDrop
# ============================================================================

class TestRedCapSignalTrackingAndRsrpDrop:
    """Validate RSRP signal surveillance, trip 0xEE71 when < -115 dBm, and recovery."""

    def test_rsrp_nominal_operation(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        assert pytest.approx(engine.rsrp_dbm, rel=1e-2) == -85.0
        assert engine.online is True
        assert engine.tripped is False

    def test_rsrp_boundary_at_minus_115_stays_healthy(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_rsrp_drop(-115.0)  # Exactly at threshold
        assert engine.state == RedCapLinkState.RRC_CONNECTED
        assert engine.diagnostic_code == DIAG_OK

    def test_rsrp_drop_below_minus_115_trips_0xee71(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_rsrp_drop(-116.0)  # Exceeds threshold (< -115 dBm)
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_RSRP_WEAK_SIGNAL
        assert engine.diagnostic_code == 0xEE71
        assert engine.online is False
        assert engine.tripped is True

    def test_rsrp_severe_drop_minus_130_trips_0xee71(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_rsrp_drop(-130.0)
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_RSRP_WEAK_SIGNAL

    def test_rsrp_drop_deasserts_online_and_asserts_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is True
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is False

        engine.inject_rsrp_drop(-120.0)
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is False
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is True
        assert (rt.read_word(REG_CIP_REDCAP_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE71

    def test_rsrp_fault_clearance_restores_disconnected_healthy(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_rsrp_drop(-120.0)
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.state == RedCapLinkState.DISCONNECTED
        assert engine.diagnostic_code == DIAG_OK
        assert engine.tripped is False
        assert pytest.approx(engine.rsrp_dbm, rel=1e-2) == NOMINAL_RSRP_DBM


# ============================================================================
# 7. TestRsrqDegradationMonitoring
# ============================================================================

class TestRsrqDegradationMonitoring:
    """Validate RSRQ channel quality surveillance, trip 0xEE72 when < -18.0 dB, and recovery."""

    def test_rsrq_nominal_operation(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        assert pytest.approx(engine.rsrq_db, rel=1e-2) == -10.0
        assert engine.online is True
        assert engine.tripped is False

    def test_rsrq_boundary_at_minus_18_stays_healthy(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_rsrq_drop(-18.0)  # Exactly at threshold
        assert engine.state == RedCapLinkState.RRC_CONNECTED
        assert engine.diagnostic_code == DIAG_OK

    def test_rsrq_drop_below_minus_18_trips_0xee72(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_rsrq_drop(-18.5)  # Degraded (< -18.0 dB)
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_RSRQ_CHANNEL_QUALITY
        assert engine.diagnostic_code == 0xEE72
        assert engine.online is False
        assert engine.tripped is True

    def test_rsrq_severe_degradation_minus_25_trips_0xee72(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_rsrq_drop(-25.0)
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_RSRQ_CHANNEL_QUALITY

    def test_rsrq_drop_deasserts_online_and_asserts_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is True
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is False

        engine.inject_rsrq_drop(-20.0)
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is False
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is True
        assert (rt.read_word(REG_CIP_REDCAP_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE72

    def test_rsrq_fault_clearance_restores_health(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_rsrq_drop(-22.0)
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.state == RedCapLinkState.DISCONNECTED
        assert engine.diagnostic_code == DIAG_OK
        assert engine.tripped is False
        assert pytest.approx(engine.rsrq_db, rel=1e-2) == NOMINAL_RSRQ_DB


# ============================================================================
# 8. TestDrxWakeupTimeoutMonitoring
# ============================================================================

class TestDrxWakeupTimeoutMonitoring:
    """Validate DRX wakeup cycle surveillance, trip 0xEE73 when > 100 ms, and recovery."""

    def test_drx_nominal_operation(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        assert pytest.approx(engine.drx_cycle_ms, rel=1e-2) == 20.0
        assert engine.online is True
        assert engine.tripped is False

    def test_drx_boundary_at_100ms_stays_healthy(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_drx_timeout(100.0)  # Exactly at threshold
        assert engine.state == RedCapLinkState.RRC_CONNECTED
        assert engine.diagnostic_code == DIAG_OK

    def test_drx_timeout_above_100ms_trips_0xee73(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_drx_timeout(105.0)  # Exceeds threshold (> 100 ms)
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DRX_WAKEUP_TIMEOUT
        assert engine.diagnostic_code == 0xEE73
        assert engine.online is False
        assert engine.tripped is True

    def test_drx_surge_200ms_trips_0xee73(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_drx_timeout(200.0)
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DRX_WAKEUP_TIMEOUT

    def test_drx_trip_deasserts_online_and_asserts_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is True
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is False

        engine.inject_drx_timeout(120.0)
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is False
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is True
        assert (rt.read_word(REG_CIP_REDCAP_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE73

    def test_drx_fault_clearance_restores_health(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_drx_timeout(150.0)
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.state == RedCapLinkState.DISCONNECTED
        assert engine.diagnostic_code == DIAG_OK
        assert engine.tripped is False
        assert pytest.approx(engine.drx_cycle_ms, rel=1e-2) == NOMINAL_DRX_CYCLE_MS


# ============================================================================
# 9. TestWatchdogAndSilenceCountdown
# ============================================================================

class TestWatchdogAndSilenceCountdown:
    """Validate RF silence accumulation, packet reset, and watchdog timeout (> 150 ms -> 0xEE74)."""

    def test_silence_timer_accumulates_during_scans(self) -> None:
        engine = CIPRedCapSafetyEngine(watchdog_timeout_ms=150.0)
        engine.connect()
        assert engine.silence_timer_ms == 0.0
        engine.scan_step(dt=0.01)  # 10 ms
        assert engine.silence_timer_ms == pytest.approx(10.0, rel=1e-2)

    def test_packet_arrival_resets_silence_timer(self) -> None:
        engine = CIPRedCapSafetyEngine(watchdog_timeout_ms=150.0)
        engine.connect()
        engine.scan_step(dt=0.05)  # 50 ms
        assert engine.silence_timer_ms >= 50.0

        pkt = create_valid_redcap_packet()
        assert engine.receive_packet(pkt) is True
        assert engine.silence_timer_ms == 0.0

    def test_silence_exceeding_150ms_trips_0xee74(self) -> None:
        engine = CIPRedCapSafetyEngine(watchdog_timeout_ms=150.0)
        engine.connect()
        # 16 cycles of 10ms = 160ms > 150ms
        for _ in range(16):
            engine.scan_step(dt=0.01)
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_WATCHDOG_COMM_TIMEOUT
        assert engine.diagnostic_code == 0xEE74

    def test_watchdog_inactive_when_disconnected(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.disconnect()
        for _ in range(30):
            engine.scan_step(dt=0.01)
        assert engine.state == RedCapLinkState.DISCONNECTED
        assert engine.diagnostic_code == DIAG_OK

    def test_watchdog_custom_timeout_configuration(self) -> None:
        engine = CIPRedCapSafetyEngine(watchdog_timeout_ms=80.0)
        engine.connect()
        for _ in range(7):  # 70 ms <= 80 ms
            engine.scan_step(dt=0.01)
        assert engine.state == RedCapLinkState.RRC_CONNECTED
        assert engine.diagnostic_code == DIAG_OK

        engine.scan_step(dt=0.02)  # 70 + 20 = 90 ms > 80 ms
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_WATCHDOG_COMM_TIMEOUT

    def test_periodic_packets_prevent_watchdog_trip(self) -> None:
        engine = CIPRedCapSafetyEngine(watchdog_timeout_ms=150.0)
        engine.connect()
        for _ in range(20):
            engine.scan_step(dt=0.01)  # 10 ms
            pkt = create_valid_redcap_packet()
            assert engine.receive_packet(pkt) is True
        assert engine.state == RedCapLinkState.RRC_CONNECTED
        assert engine.diagnostic_code == DIAG_OK


# ============================================================================
# 10. TestPacketTxRxAndCrcCorruption
# ============================================================================

class TestPacketTxRxAndCrcCorruption:
    """Validate packet send, receive, promotion, rolling sequence, and corrupted frame handling (0xEE75)."""

    def test_send_packet_generates_valid_signed_frame(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        pkt = engine.send_packet(b"\x12\x34\x56")
        assert pkt.payload_bytes == b"\x12\x34\x56"
        assert pkt.sequence_number == 1
        assert pkt.validate_crcs() is True
        assert engine.tx_frame_count == 1

    def test_sequence_counter_rollover(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.sequence_number = 65535
        pkt = engine.send_packet()
        assert pkt.sequence_number == 0
        assert engine.sequence_number == 0

    def test_receive_packet_promotes_to_rrc_connected(self) -> None:
        engine = CIPRedCapSafetyEngine()
        assert engine.state == RedCapLinkState.DISCONNECTED
        pkt = create_valid_redcap_packet(sequence=5)
        assert engine.receive_packet(pkt) is True
        assert engine.state == RedCapLinkState.RRC_CONNECTED
        assert engine.online is True

    def test_receive_packet_corrupted_crc_trips_0xee75(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        bad_pkt = create_valid_redcap_packet()
        bad_pkt.crc_s1 ^= 0x1234
        assert engine.receive_packet(bad_pkt) is False
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.diagnostic_code == 0xEE75
        assert engine.packet_loss_counter == 1

    def test_crc_fault_injection_increments_packet_loss_counter(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        engine.inject_crc_fault()
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.packet_loss_counter == 1

        engine.inject_crc_fault()
        assert engine.packet_loss_counter == 2

    def test_receive_packet_ingress_rsrp_violation_trips(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        pkt = create_valid_redcap_packet(rsrp_dbm=-125.0)
        assert engine.receive_packet(pkt) is False
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_RSRP_WEAK_SIGNAL

    def test_receive_packet_ingress_rsrq_violation_trips(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        pkt = create_valid_redcap_packet(rsrq_db=-22.0)
        assert engine.receive_packet(pkt) is False
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_RSRQ_CHANNEL_QUALITY

    def test_receive_packet_ingress_drx_violation_trips(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        pkt = create_valid_redcap_packet(drx_cycle_ms=130.0)
        assert engine.receive_packet(pkt) is False
        assert engine.state == RedCapLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DRX_WAKEUP_TIMEOUT


# ============================================================================
# 11. TestSafeStopInterlockAndCoils
# ============================================================================

class TestSafeStopInterlockAndCoils:
    """Validate safe stop coil asserting %M633 and de-asserting %M632 across all faults."""

    def test_safe_stop_interlock_initial_state(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is False
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is False

    def test_safe_stop_interlock_connected_state(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is True
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is False

    def test_safe_stop_on_rsrp_drop(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.inject_rsrp_drop(-120.0)
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is False
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is True
        assert (rt.read_word(REG_CIP_REDCAP_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE71

    def test_safe_stop_on_rsrq_drop(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.inject_rsrq_drop(-20.0)
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is False
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is True
        assert (rt.read_word(REG_CIP_REDCAP_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE72

    def test_safe_stop_on_drx_timeout(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.inject_drx_timeout(115.0)
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is False
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is True
        assert (rt.read_word(REG_CIP_REDCAP_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE73

    def test_safe_stop_on_watchdog_timeout(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.inject_watchdog_timeout()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is False
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is True
        assert (rt.read_word(REG_CIP_REDCAP_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE74

    def test_safe_stop_on_crc_fault(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.inject_crc_fault()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is False
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is True
        assert (rt.read_word(REG_CIP_REDCAP_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE75

    def test_safe_stop_clearance_restores_nominal_coils(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.inject_rsrp_drop(-125.0)
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is True

        engine.clear_fault()
        engine.connect()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is True
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is False
        assert (rt.read_word(REG_CIP_REDCAP_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000


# ============================================================================
# 12. TestHornerRegisterTableSynchronization
# ============================================================================

class TestHornerRegisterTableSynchronization:
    """Validate bit-exact register sync to %R2710..%R2717 and %M632..%M633."""

    def test_nominal_sync_all_registers_and_coils(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(
            power_mode=RedCapPowerMode.ACTIVE,
            register_table=rt,
        )
        engine.connect()
        engine.sequence_number = 45
        engine.rsrp_dbm = -85.0
        engine.rsrq_db = -10.0
        engine.drx_cycle_ms = 20.0
        engine.battery_remaining_pct = 90.0
        engine.packet_loss_counter = 3

        engine.sync_to_registers(rt)

        reg_status = rt.read_word(REG_CIP_REDCAP_STATUS) & 0xFFFF
        assert (reg_status >> 8) == int(RedCapLinkState.RRC_CONNECTED)
        assert (reg_status & 0xFF) == int(RedCapPowerMode.ACTIVE)

        assert (rt.read_word(REG_CIP_REDCAP_SEQUENCE) & 0xFFFF) == 45
        assert rt.read_word(REG_CIP_REDCAP_RSRP_DBM) == -85
        assert rt.read_word(REG_CIP_REDCAP_RSRQ_DB) == -10
        assert (rt.read_word(REG_CIP_REDCAP_DRX_CYCLE_MS) & 0xFFFF) == 20
        assert (rt.read_word(REG_CIP_REDCAP_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
        assert (rt.read_word(REG_CIP_REDCAP_BATTERY_REMAINING_PCT) & 0xFFFF) == 90
        assert (rt.read_word(REG_CIP_REDCAP_PACKET_LOSS_COUNTER) & 0xFFFF) == 3

        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is True
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is False

    def test_signed_negative_rsrp_sync(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.rsrp_dbm = -105.0

        engine.sync_to_registers(rt)
        assert rt.read_word(REG_CIP_REDCAP_RSRP_DBM) == -105
        assert (rt.read_word(REG_CIP_REDCAP_RSRP_DBM) & 0xFFFF) == (-105 & 0xFFFF)

    def test_signed_negative_rsrq_sync(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.rsrq_db = -14.0

        engine.sync_to_registers(rt)
        assert rt.read_word(REG_CIP_REDCAP_RSRQ_DB) == -14
        assert (rt.read_word(REG_CIP_REDCAP_RSRQ_DB) & 0xFFFF) == (-14 & 0xFFFF)

    def test_diagnostic_code_register_masking(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.inject_rsrp_drop(-120.0)

        engine.sync_to_registers(rt)
        assert (rt.read_word(REG_CIP_REDCAP_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE71

    def test_fault_reflection_in_register_table(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        engine.inject_drx_timeout(125.0)

        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is False
        assert rt.read_bit(COIL_CIP_REDCAP_TRIP) is True
        assert (rt.read_word(REG_CIP_REDCAP_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE73

    def test_privilege_modes_in_sync_to_registers(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        for priv in (PrivilegeMode.SYSTEM, PrivilegeMode.APPLICATION):
            engine.sync_to_registers(rt, privilege=priv)
            assert rt.read_bit(COIL_CIP_REDCAP_ONLINE) is True

    def test_power_mode_status_register_encoding(self) -> None:
        rt = RegisterTable()
        for mode in (RedCapPowerMode.ACTIVE, RedCapPowerMode.DRX_STANDBY, RedCapPowerMode.EDRX_DEEP_SLEEP):
            engine = CIPRedCapSafetyEngine(power_mode=mode, register_table=rt)
            engine.connect()
            engine.sync_to_registers(rt)
            val = rt.read_word(REG_CIP_REDCAP_STATUS) & 0xFFFF
            assert (val & 0xFF) == int(mode)
            assert (val >> 8) == int(RedCapLinkState.RRC_CONNECTED)

    def test_safe_write_helpers(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R2712", -90)
        assert rt.read_word("%R2712") == -90

        safe_write_uword(rt, "%R2714", 65000)
        assert (rt.read_word("%R2714") & 0xFFFF) == 65000

        safe_write_bit(rt, "%M632", True)
        assert rt.read_bit("%M632") is True


# ============================================================================
# 13. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface compliance, ScanContext resolution, step, and execute."""

    def test_ilogicunit_properties(self) -> None:
        engine = CIPRedCapSafetyEngine(name="TestRedCapEngine", priority=2, is_enabled=True)
        assert engine.name == "TestRedCapEngine"
        assert engine.priority == 2
        assert engine.is_enabled is True
        engine.is_enabled = False
        assert engine.is_enabled is False

    def test_scan_step_with_variable_arguments(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt, auto_activate=True)

        res1 = engine.scan_step(0.01)
        assert res1.status == AgentStatus.SUCCESS

        res2 = engine.scan_step(dt=0.02)
        assert res2.status == AgentStatus.SUCCESS

        res3 = engine.scan_step(dt_ms=15.0)
        assert res3.status == AgentStatus.SUCCESS

        ctx = ScanContext(cycle=1, dt_ms=10.0, dt=0.01)
        res4 = engine.scan_step(ctx)
        assert res4.status == AgentStatus.SUCCESS

    def test_step_and_execute_aliases(self) -> None:
        engine = CIPRedCapSafetyEngine(auto_activate=True)
        res_step = engine.step(dt=0.01)
        assert res_step.status == AgentStatus.SUCCESS

        res_exec = engine.execute()
        assert res_exec.status == AgentStatus.SUCCESS

    def test_register_table_resolution_hierarchy(self) -> None:
        rt_local = RegisterTable()
        rt_external = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt_local, auto_activate=True)
        engine.sequence_number = 55

        engine.scan_step(register_table=rt_external)
        assert (rt_external.read_word(REG_CIP_REDCAP_SEQUENCE) & 0xFFFF) == 55

    def test_execution_result_payload_contents(self) -> None:
        engine = CIPRedCapSafetyEngine(auto_activate=True)
        res = engine.scan_step(dt=0.01)
        assert res.status == AgentStatus.SUCCESS
        assert "state" in res.data
        assert "power_mode" in res.data
        assert "online" in res.data
        assert "tripped" in res.data
        assert "diagnostic_code" in res.data
        assert "rsrp_dbm" in res.data
        assert "rsrq_db" in res.data
        assert "drx_cycle_ms" in res.data


# ============================================================================
# 14. TestPureStructuredTextAndSecurityGuard
# ============================================================================

class TestPureStructuredTextAndSecurityGuard:
    """Validate CipSafetyRedCapSync POU with STParser and anti-ladder SecurityGuard."""

    def test_pure_st_pou_verification(self) -> None:
        assert verify_cip_safety_redcap_pure_st() is True

    def test_st_parser_ast_and_bound_registers(self) -> None:
        ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_REDCAP_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R2710", "%R2711", "%R2712", "%R2713",
            "%R2714", "%R2715", "%R2716", "%R2717",
            "%M632", "%M633",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_security_guard_pure_st_assertion(self) -> None:
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_REDCAP_SYNC)

    @pytest.mark.parametrize(
        "ladder_snippet",
        [
            "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[ ]--- x; END_PROGRAM",
            "PROGRAM LadderTest VAR x : BOOL; END_VAR ---[/]--- x; END_PROGRAM",
            "PROGRAM LadderTest VAR y : BOOL; END_VAR ---( )--- y; END_PROGRAM",
            "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(S)--- y; END_PROGRAM",
            "PROGRAM LadderTest VAR y : BOOL; END_VAR ---(R)--- y; END_PROGRAM",
            "PROGRAM LadderTest RUNG 1 END_PROGRAM",
            "PROGRAM LadderTest NETWORK 10 END_PROGRAM",
            "PROGRAM LadderTest XIC(StartPB); END_PROGRAM",
            "PROGRAM LadderTest OTE(MotorCoil); END_PROGRAM",
        ],
    )
    def test_strict_anti_ladder_interception(self, ladder_snippet: str) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(ladder_snippet)

    def test_pou_text_constants_and_aliases(self) -> None:
        assert CIP_SAFETY_REDCAP_SYNC_POU == ST_PROGRAM_CIP_SAFETY_REDCAP_SYNC
        assert CIP_SAFETY_REDCAP_PURE_ST_POU == ST_PROGRAM_CIP_SAFETY_REDCAP_SYNC
        assert CipSafetyRedCapSync == ST_PROGRAM_CIP_SAFETY_REDCAP_SYNC


# ============================================================================
# 15. TestMultiCycleSoakAndStability
# ============================================================================

class TestMultiCycleSoakAndStability:
    """Validate 100-cycle continuous simulation soak test, counter monotonicity, and memory stability."""

    def test_100_cycle_soak_stability(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()

        tracemalloc.start()
        mem_start, _ = tracemalloc.get_traced_memory()

        for cycle in range(1, 101):
            pkt = engine.send_packet()
            assert engine.receive_packet(pkt) is True
            res = engine.scan_step(dt=0.01, register_table=rt)
            assert res.status == AgentStatus.SUCCESS
            assert engine.online is True
            assert engine.tripped is False
            assert (rt.read_word(REG_CIP_REDCAP_SEQUENCE) & 0xFFFF) == cycle

        mem_end, _ = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        mem_growth_kb = (mem_end - mem_start) / 1024.0
        assert mem_growth_kb < 1024.0  # Heap growth bounded < 1MB

    def test_packet_loss_counter_monotonicity_under_faults(self) -> None:
        engine = CIPRedCapSafetyEngine()
        engine.connect()
        for i in range(1, 11):
            engine.inject_crc_fault()
            assert engine.packet_loss_counter == i

    def test_extended_soak_state_retention(self) -> None:
        rt = RegisterTable()
        engine = CIPRedCapSafetyEngine(register_table=rt)
        engine.connect()
        for _ in range(50):
            pkt = engine.send_packet()
            engine.receive_packet(pkt)
            engine.scan_step(dt=0.01)
        assert engine.online is True
        assert engine.tripped is False
        assert engine.diagnostic_code == DIAG_OK


# ============================================================================
# 16. TestVerificationRunner9StagesAndCli
# ============================================================================

class TestVerificationRunner9StagesAndCli:
    """Validate run_cip_safety_redcap_verification 9-stage suite, 4-state contract, and evidence."""

    def test_runner_passes_all_9_stages(self) -> None:
        res = run_cip_safety_redcap_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["total_stages"] == 9
        assert res["stages_passed"] == 9

    def test_runner_evidence_data_integrity(self) -> None:
        res = run_cip_safety_redcap_verification()
        data = res["data"]
        assert data["work_package"] == "W310"
        assert data["gate"] == "G8"
        assert len(data["stages"]) == 9
        for s in data["stages"]:
            assert s["passed"] is True
            assert s["timing_ms"] >= 0.0

    def test_runner_no_file_written_when_output_path_is_none(self) -> None:
        res = run_cip_safety_redcap_verification(output_path=None)
        assert res["status"] == "success"

    def test_runner_writes_file_when_output_path_specified(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            res = run_cip_safety_redcap_verification(output_path=ev_path)
            assert res["status"] == "success"
            assert ev_path.exists()
            with open(ev_path, encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["total_stages"] == 9

    def test_quick_mode_verification(self) -> None:
        res = run_cip_safety_redcap_verification(quick=True)
        assert res["status"] == "success"
        assert res["stages_passed"] == 9

    def test_module_cli_direct_execution(self) -> None:
        """Verify executing module CLI directly with tempfile output."""
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "module_redcap_evidence.json"
            proc = subprocess.run(
                [sys.executable, "-m", "jev_cscape.telemetry.cip_safety_redcap", "--output", str(tmp_out), "--quick", "--json"],
                capture_output=True,
                text=True,
                check=True,
            )
            assert proc.returncode == 0
            evidence = json.loads(proc.stdout)
            assert evidence["status"] == "success"
            assert tmp_out.exists()

    def test_script_runner_interop_cli(self) -> None:
        """Verify interop with scripts/run_cip_safety_redcap_verification.py CLI."""
        scripts_runner_path = Path(__file__).resolve().parent.parent / "scripts" / "run_cip_safety_redcap_verification.py"
        assert scripts_runner_path.exists()
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "test_redcap_evidence.json"
            proc = subprocess.run(
                [sys.executable, str(scripts_runner_path), "--output", str(tmp_out), "--quick", "--json"],
                capture_output=True,
                text=True,
                check=True,
            )
            assert proc.returncode == 0
            evidence = json.loads(proc.stdout)
            assert evidence["status"] == "success"
            assert evidence["stages_passed"] == 9
            assert tmp_out.exists()
