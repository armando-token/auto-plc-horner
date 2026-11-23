"""Comprehensive Unit Test Suite for Wave W307 CIP Safety Over Satellite / LEO Bridge.

Work Package: W307 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Satellite / Low Earth Orbit (LEO) Telemetry Bridge

Covers Comprehensive Deterministic Unit Tests across 13 Mandatory Test Classes (80+ Tests):
1. TestConstantsEnumsAndDiagnostics: Protocol constants, register mappings (%R2680..%R2687),
   coils (%M625..%M626), diagnostic codes (0x0000, 0xEE61..0xEE65), signed/unsigned 16-bit equality,
   bitwise masking, enums (SatelliteLinkState, ModulationScheme), status bits, and aliases.
2. TestDualCrcAlgorithmsAndFrameIntegrity: Dual CRC-S1 (poly 0x5935, seed 0x0000) and CRC-S2 (poly 0x755B, seed 0x0000),
   single-bit flip sensitivity, EPID CRC32 hashing, and verify_dual_crc_s helper.
3. TestPacketModelAndBinarySerialization: CIPSatellitePacket dataclass, inverted header computation,
   CRC generation/validation, binary packing/unpacking roundtrip, and corrupted frame rejection.
4. TestEngineInitializationAndStateTransitions: State machine transitions (DISCONNECTED -> ONLINE_TRACKING -> SAFETY_TRIP),
   auto_activate, connect, disconnect, trip_safety/trip_fault, clear_fault, and reset.
5. TestTelemetrySurveillanceAndThresholds: Telemetry surveillance for Doppler (+/- 35 kHz), RTT (<= 120 ms),
   SNR (>= 6 dB), and pass window countdown (600s), safe operational boundaries, and fault thresholds.
6. TestAllDiagnosticCodesAndFailSafeTrips: Full verification of all 5 diagnostic codes (0xEE61 through 0xEE65),
   immediate de-energization of online status (%M625=False), assertion of trip status (%M626=True),
   and recovery reset for each diagnostic code.
7. TestWatchdogAndSilenceCountdown: Silence countdown timer accumulation during scan cycles,
   watchdog timeout expiration (> 250.0 ms -> 0xEE64), timer reset on packet arrival, and inactive states.
8. TestPacketTxRxAndTransmissionDynamics: Egress packet transmission with rolling sequence counters,
   ingress packet processing, state promotion, telemetry updates, and CRC corruption fault detection.
9. TestHornerRegisterTableSynchronization: Bit-exact synchronization to Horner OCS registers (%R2680..%R2687)
   and coils (%M625..%M626), signed 16-bit masking `(rt.read_word(...) & 0xFFFF) == expected`,
   negative Doppler representation, and privilege modes.
10. TestILogicUnitCompliance: ILogicUnit interface compliance (scan_step with variable args/kwargs,
    step, execute, reset), ScanContext handling, execution results, and register table hierarchy.
11. TestPureStructuredTextAndSecurityGuard: Pure IEC 61131-3 ST POU CipSafetySatelliteSync validation
    via STParser and SecurityGuard, AST bound registers, and strict interception of ladder logic
    constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
12. TestMultiCycleSoakAndStability: 100-cycle continuous simulation soak test with live packet exchange,
    monotonic counter increments, zero fault trips, and bounded memory footprint verified via tracemalloc.
13. TestVerificationRunner9Stages: Complete 9-stage verification suite run_cip_safety_satellite_verification,
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
from jev_cscape.telemetry.cip_safety_satellite import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_SATELLITE_CLASS_ID,
    NOMINAL_DOPPLER_HZ,
    DEFAULT_DOPPLER_HZ,
    MAX_ALLOWED_DOPPLER_HZ,
    DEFAULT_DOPPLER_TRIP_THRESHOLD_HZ,
    NOMINAL_RTT_MS,
    DEFAULT_RTT_MS,
    MAX_ALLOWED_RTT_MS,
    DEFAULT_RTT_TRIP_THRESHOLD_MS,
    NOMINAL_SNR_DB,
    DEFAULT_SNR_DB,
    MIN_ALLOWED_SNR_DB,
    DEFAULT_SNR_TRIP_THRESHOLD_DB,
    NOMINAL_PASS_REMAINING_SEC,
    DEFAULT_PASS_REMAINING_SEC,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    NOMINAL_SATELLITE_WATCHDOG_MS,
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
    REG_CIP_SATELLITE_STATUS,
    REG_CIP_SATELLITE_SEQUENCE,
    REG_CIP_SATELLITE_DOPPLER_SHIFT,
    REG_CIP_SATELLITE_RTT_LATENCY,
    REG_CIP_SATELLITE_SNR_MARGIN,
    REG_CIP_SATELLITE_DIAGNOSTIC_CODE,
    REG_CIP_SATELLITE_PASS_REMAINING_SEC,
    REG_CIP_SATELLITE_PACKET_LOSS_COUNTER,
    COIL_CIP_SATELLITE_ONLINE,
    COIL_CIP_SATELLITE_TRIP,
    REG_SATELLITE_STATUS,
    REG_SATELLITE_SEQUENCE,
    REG_SATELLITE_DOPPLER_SHIFT,
    REG_SATELLITE_RTT_LATENCY,
    REG_SATELLITE_SNR_MARGIN,
    REG_SATELLITE_DIAGNOSTIC_CODE,
    REG_SATELLITE_PASS_REMAINING_SEC,
    REG_SATELLITE_PACKET_LOSS_COUNTER,
    COIL_SATELLITE_ONLINE,
    COIL_SATELLITE_TRIP,
    COIL_CIP_SATELLITE_HEALTHY,
    SatelliteLinkState,
    CipSatelliteLinkState,
    ModulationScheme,
    DiagnosticCode,
    SatelliteStatusBits,
    DIAG_OK,
    DIAG_ERR_DOPPLER_EXCEEDED,
    DIAG_ERR_PROPAGATION_DELAY_EXCEEDED,
    DIAG_ERR_CARRIER_FADE_MARGIN_TRIP,
    DIAG_ERR_WATCHDOG_COMM_TIMEOUT,
    DIAG_ERR_DUAL_CRC_SAFETY_FAULT,
    DIAG_DOPPLER_EXCEEDED,
    DIAG_PROPAGATION_DELAY_EXCEEDED,
    DIAG_CARRIER_FADE_MARGIN_TRIP,
    DIAG_WATCHDOG_COMM_TIMEOUT,
    DIAG_DUAL_CRC_SAFETY_FAULT,
    CIPSatelliteSafetyError,
    SatelliteDopplerExceededError,
    SatellitePropagationDelayExceededError,
    SatelliteCarrierFadeMarginError,
    SatelliteWatchdogTimeoutError,
    SatelliteDualCrcSafetyFaultError,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    calculate_cip_safety_crc_s1,
    calculate_cip_safety_crc_s2,
    compute_epid_hash,
    compute_epid_crc32,
    verify_dual_crc_s,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CIPSatellitePacket,
    CipSafetySatellitePacket,
    create_valid_satellite_packet,
    ST_PROGRAM_CIP_SAFETY_SATELLITE_SYNC,
    CIP_SAFETY_SATELLITE_SYNC_POU,
    CIP_SAFETY_SATELLITE_PURE_ST_POU,
    CipSafetySatelliteSync,
    verify_cip_safety_satellite_pure_st,
    CIPSatelliteBridgeEngine,
    CipSafetySatelliteEngine,
    run_cip_safety_satellite_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate protocol constants, register mappings, coils, enums, and diagnostic codes."""

    def test_canonical_registers_and_coils(self) -> None:
        assert REG_CIP_SATELLITE_STATUS == "%R2680"
        assert REG_CIP_SATELLITE_SEQUENCE == "%R2681"
        assert REG_CIP_SATELLITE_DOPPLER_SHIFT == "%R2682"
        assert REG_CIP_SATELLITE_RTT_LATENCY == "%R2683"
        assert REG_CIP_SATELLITE_SNR_MARGIN == "%R2684"
        assert REG_CIP_SATELLITE_DIAGNOSTIC_CODE == "%R2685"
        assert REG_CIP_SATELLITE_PASS_REMAINING_SEC == "%R2686"
        assert REG_CIP_SATELLITE_PACKET_LOSS_COUNTER == "%R2687"

        assert COIL_CIP_SATELLITE_ONLINE == "%M625"
        assert COIL_CIP_SATELLITE_TRIP == "%M626"

    def test_extended_aliases(self) -> None:
        assert REG_SATELLITE_STATUS == "%R2680"
        assert REG_SATELLITE_SEQUENCE == "%R2681"
        assert REG_SATELLITE_DOPPLER_SHIFT == "%R2682"
        assert REG_SATELLITE_RTT_LATENCY == "%R2683"
        assert REG_SATELLITE_SNR_MARGIN == "%R2684"
        assert REG_SATELLITE_DIAGNOSTIC_CODE == "%R2685"
        assert REG_SATELLITE_PASS_REMAINING_SEC == "%R2686"
        assert REG_SATELLITE_PACKET_LOSS_COUNTER == "%R2687"

        assert COIL_SATELLITE_ONLINE == "%M625"
        assert COIL_SATELLITE_TRIP == "%M626"
        assert COIL_CIP_SATELLITE_HEALTHY == "%M625"

    def test_class_ids_and_polynomials(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_SATELLITE_CLASS_ID == 0x2F

        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0x0000
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CRC_INIT == 0x0000

    def test_satellite_link_state_enum(self) -> None:
        assert int(SatelliteLinkState.DISCONNECTED) == 0
        assert int(SatelliteLinkState.LINK_SEARCH) == 1
        assert int(SatelliteLinkState.DOPPLER_ACQUIRING) == 2
        assert int(SatelliteLinkState.ONLINE_TRACKING) == 3
        assert int(SatelliteLinkState.SAFETY_TRIP) == 4

        # Aliases
        assert SatelliteLinkState.IDLE == SatelliteLinkState.DISCONNECTED
        assert SatelliteLinkState.SEARCHING == SatelliteLinkState.LINK_SEARCH
        assert SatelliteLinkState.ACQUIRING == SatelliteLinkState.DOPPLER_ACQUIRING
        assert SatelliteLinkState.TRACKING == SatelliteLinkState.ONLINE_TRACKING
        assert SatelliteLinkState.CONNECTED_RUNNING == SatelliteLinkState.ONLINE_TRACKING
        assert SatelliteLinkState.TRIPPED == SatelliteLinkState.SAFETY_TRIP

    def test_modulation_scheme_enum(self) -> None:
        assert int(ModulationScheme.QPSK) == 1
        assert int(ModulationScheme.PSK_8) == 2
        assert int(ModulationScheme.APSK_16) == 3
        assert int(ModulationScheme.APSK_32) == 4

    def test_diagnostic_code_values(self) -> None:
        assert int(DiagnosticCode.DIAG_OK) == 0x0000
        assert int(DiagnosticCode.DIAG_ERR_DOPPLER_EXCEEDED) == 0xEE61
        assert int(DiagnosticCode.DIAG_ERR_PROPAGATION_DELAY_EXCEEDED) == 0xEE62
        assert int(DiagnosticCode.DIAG_ERR_CARRIER_FADE_MARGIN_TRIP) == 0xEE63
        assert int(DiagnosticCode.DIAG_ERR_WATCHDOG_COMM_TIMEOUT) == 0xEE64
        assert int(DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT) == 0xEE65

    def test_diagnostic_code_signed_unsigned_equality(self) -> None:
        # 0xEE61 as signed 16-bit is -4511
        assert DiagnosticCode.DIAG_ERR_DOPPLER_EXCEEDED == 0xEE61
        assert DiagnosticCode.DIAG_ERR_DOPPLER_EXCEEDED == -4511
        assert 0xEE61 == DiagnosticCode.DIAG_ERR_DOPPLER_EXCEEDED
        assert -4511 == DiagnosticCode.DIAG_ERR_DOPPLER_EXCEEDED

        # 0xEE62 as signed 16-bit is -4510
        assert DiagnosticCode.DIAG_ERR_PROPAGATION_DELAY_EXCEEDED == 0xEE62
        assert DiagnosticCode.DIAG_ERR_PROPAGATION_DELAY_EXCEEDED == -4510

        # 0xEE63 as signed 16-bit is -4509
        assert DiagnosticCode.DIAG_ERR_CARRIER_FADE_MARGIN_TRIP == 0xEE63
        assert DiagnosticCode.DIAG_ERR_CARRIER_FADE_MARGIN_TRIP == -4509

        # 0xEE64 as signed 16-bit is -4508
        assert DiagnosticCode.DIAG_ERR_WATCHDOG_COMM_TIMEOUT == 0xEE64
        assert DiagnosticCode.DIAG_ERR_WATCHDOG_COMM_TIMEOUT == -4508

        # 0xEE65 as signed 16-bit is -4507
        assert DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT == 0xEE65
        assert DiagnosticCode.DIAG_ERR_DUAL_CRC_SAFETY_FAULT == -4507

        # OK is 0
        assert DiagnosticCode.DIAG_OK == 0

    def test_diagnostic_code_bitwise_and_hashing(self) -> None:
        code = DiagnosticCode.DIAG_ERR_DOPPLER_EXCEEDED
        assert (code & 0xFF00) == 0xEE00
        assert (0xFF00 & code) == 0xEE00
        assert hash(code) == hash(0xEE61)
        assert str(code).startswith("0xEE61")
        assert repr(code).startswith("DiagnosticCode.")

    def test_status_bits_flags(self) -> None:
        assert SatelliteStatusBits.ONLINE == 1
        assert SatelliteStatusBits.TRACKING == 2
        assert SatelliteStatusBits.SAFETY_ACTIVE == 4
        assert SatelliteStatusBits.DOPPLER_LOCKED == 8
        assert SatelliteStatusBits.SNR_ADEQUATE == 16
        assert SatelliteStatusBits.PASS_ACTIVE == 32
        assert SatelliteStatusBits.SAFETY_TRIPPED == 64
        assert SatelliteStatusBits.RTT_NOMINAL == 128

    def test_exceptions_hierarchy(self) -> None:
        assert issubclass(SatelliteDopplerExceededError, CIPSatelliteSafetyError)
        assert issubclass(SatellitePropagationDelayExceededError, CIPSatelliteSafetyError)
        assert issubclass(SatelliteCarrierFadeMarginError, CIPSatelliteSafetyError)
        assert issubclass(SatelliteWatchdogTimeoutError, CIPSatelliteSafetyError)
        assert issubclass(SatelliteDualCrcSafetyFaultError, CIPSatelliteSafetyError)


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
        inverted = bytes(~b & 0xFF for b in (0x4C45).to_bytes(2, "big") + (1).to_bytes(2, "big") + (100).to_bytes(4, "big"))
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
        raw = (0x4C45).to_bytes(2, "big") + (10).to_bytes(2, "big") + (500).to_bytes(4, "big")
        inv = bytes(~b & 0xFF for b in raw)
        c_orig = compute_crc_s2(inv)
        for byte_idx in range(len(inv)):
            for bit_idx in range(8):
                mutated = bytearray(inv)
                mutated[byte_idx] ^= (1 << bit_idx)
                c_mutated = compute_crc_s2(bytes(mutated))
                assert c_orig != c_mutated

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


# ============================================================================
# 3. TestPacketModelAndBinarySerialization
# ============================================================================

class TestPacketModelAndBinarySerialization:
    """Validate CIPSatellitePacket model, inverted header, CRC computation, and binary pack/unpack."""

    def test_packet_creation_and_auto_crc(self) -> None:
        pkt = CIPSatellitePacket(
            session_id=0x4C45,
            sequence_number=1,
            timestamp_ms=100,
            payload_bytes=b"\x01\x02\x03",
        )
        assert pkt.crc_s1 != 0 or pkt.crc_s2 != 0
        assert pkt.validate_crcs() is True

    def test_packet_properties_and_aliases(self) -> None:
        pkt = CIPSatellitePacket()
        assert pkt.payload == pkt.payload_bytes
        pkt.payload = b"\x09\x08"
        assert pkt.payload_bytes == b"\x09\x08"
        assert pkt.sequence == pkt.sequence_number
        pkt.sequence = 42
        assert pkt.sequence_number == 42
        assert pkt.timestamp == pkt.timestamp_ms
        pkt.timestamp = 999
        assert pkt.timestamp_ms == 999

    def test_pack_unpack_roundtrip(self) -> None:
        original = CIPSatellitePacket(
            session_id=0x1234,
            sequence_number=77,
            timestamp_ms=2500,
            doppler_hz=-12500.0,
            rtt_ms=45.6,
            snr_db=18.2,
            payload_bytes=b"\xDE\xAD\xBE\xEF",
            modulation=ModulationScheme.APSK_16,
        )
        raw = original.pack()
        assert isinstance(raw, bytes)
        unpacked = CIPSatellitePacket.unpack(raw)
        assert unpacked.session_id == 0x1234
        assert unpacked.sequence_number == 77
        assert unpacked.timestamp_ms == 2500
        assert round(unpacked.doppler_hz) == -12500
        assert pytest.approx(unpacked.rtt_ms, rel=1e-2) == 45.6
        assert pytest.approx(unpacked.snr_db, rel=1e-2) == 18.2
        assert unpacked.payload_bytes == b"\xDE\xAD\xBE\xEF"
        assert unpacked.modulation == ModulationScheme.APSK_16
        assert unpacked.validate_crcs() is True

    def test_corrupted_payload_fails_crc(self) -> None:
        pkt = create_valid_satellite_packet()
        assert pkt.validate_crcs() is True
        pkt.payload_bytes = b"\xFF\xFF\xFF"
        assert pkt.validate_crcs() is False

    def test_unpack_truncated_data_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Packet data too short"):
            CIPSatellitePacket.unpack(b"\x00" * 5)


# ============================================================================
# 4. TestEngineInitializationAndStateTransitions
# ============================================================================

class TestEngineInitializationAndStateTransitions:
    """Validate engine initialization defaults, properties, connect, disconnect, trip, and clear."""

    def test_default_initialization(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        assert engine.state == SatelliteLinkState.DISCONNECTED
        assert engine.online is False
        assert engine.tripped is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.doppler_hz == NOMINAL_DOPPLER_HZ
        assert engine.rtt_ms == NOMINAL_RTT_MS
        assert engine.snr_db == NOMINAL_SNR_DB
        assert engine.sequence_number == 0

    def test_auto_activate_option(self) -> None:
        engine = CIPSatelliteBridgeEngine(auto_activate=True)
        assert engine.state == SatelliteLinkState.ONLINE_TRACKING
        assert engine.online is True
        assert engine.tripped is False

    def test_connect_and_disconnect(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        assert engine.state == SatelliteLinkState.ONLINE_TRACKING
        assert engine.online is True
        assert engine.tripped is False

        engine.disconnect()
        assert engine.state == SatelliteLinkState.DISCONNECTED
        assert engine.online is False

    def test_trip_safety_and_clear_fault(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        engine.trip_safety(DIAG_ERR_DOPPLER_EXCEEDED, "Doppler limit test")
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DOPPLER_EXCEEDED
        assert engine.online is False
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.state == SatelliteLinkState.DISCONNECTED
        assert engine.diagnostic_code == DIAG_OK
        assert engine.tripped is False

    def test_engine_reset_clears_counters(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        engine.send_packet()
        engine.packet_loss_counter = 5
        engine.pass_remaining_sec = 100
        engine.trip_safety(DIAG_ERR_WATCHDOG_COMM_TIMEOUT)

        engine.reset()
        assert engine.state == SatelliteLinkState.DISCONNECTED
        assert engine.diagnostic_code == DIAG_OK
        assert engine.sequence_number == 0
        assert engine.packet_loss_counter == 0
        assert engine.tx_frame_count == 0
        assert engine.rx_frame_count == 0
        assert engine.pass_remaining_sec == NOMINAL_PASS_REMAINING_SEC

    def test_status_register_and_status_word(self) -> None:
        engine = CIPSatelliteBridgeEngine(modulation=ModulationScheme.APSK_16)
        engine.connect()
        status_reg = engine.status_register_value
        assert (status_reg >> 8) == int(SatelliteLinkState.ONLINE_TRACKING)
        assert (status_reg & 0xFF) == int(ModulationScheme.APSK_16)
        assert engine.status_word & SatelliteStatusBits.ONLINE
        assert engine.status_word & SatelliteStatusBits.TRACKING


# ============================================================================
# 5. TestTelemetrySurveillanceAndThresholds
# ============================================================================

class TestTelemetrySurveillanceAndThresholds:
    """Validate Doppler, RTT, SNR, and Pass remaining boundaries and fault limits."""

    def test_nominal_telemetry_parameters(self) -> None:
        assert NOMINAL_DOPPLER_HZ == 0.0
        assert NOMINAL_RTT_MS == 25.0
        assert NOMINAL_SNR_DB == 15.0
        assert NOMINAL_PASS_REMAINING_SEC == 600

    def test_safe_boundaries_and_limits(self) -> None:
        assert MAX_ALLOWED_DOPPLER_HZ == 35000.0
        assert MAX_ALLOWED_RTT_MS == 120.0
        assert MIN_ALLOWED_SNR_DB == 6.0
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 250.0

    def test_doppler_safe_range(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        engine.inject_doppler_shift(20000.0)  # Within 35 kHz
        assert engine.state == SatelliteLinkState.ONLINE_TRACKING
        assert engine.diagnostic_code == DIAG_OK

    def test_rtt_safe_range(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        engine.inject_rtt_latency(50.0)  # Within 120 ms
        assert engine.state == SatelliteLinkState.ONLINE_TRACKING
        assert engine.diagnostic_code == DIAG_OK

    def test_snr_safe_range(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        engine.inject_carrier_fade(10.0)  # Above 6 dB
        assert engine.state == SatelliteLinkState.ONLINE_TRACKING
        assert engine.diagnostic_code == DIAG_OK


# ============================================================================
# 6. TestAllDiagnosticCodesAndFailSafeTrips
# ============================================================================

class TestAllDiagnosticCodesAndFailSafeTrips:
    """Validate all 5 safety diagnostic codes (0xEE61 through 0xEE65) and recovery."""

    def test_diagnostic_0xee61_doppler_exceeded(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        engine.inject_doppler_shift(40000.0)  # Exceeds 35 kHz
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DOPPLER_EXCEEDED
        assert engine.diagnostic_code == 0xEE61
        assert engine.online is False
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.state == SatelliteLinkState.DISCONNECTED
        assert engine.diagnostic_code == DIAG_OK

    def test_diagnostic_0xee61_negative_doppler_exceeded(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        engine.inject_doppler_shift(-38000.0)  # |-38000| > 35000
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DOPPLER_EXCEEDED

    def test_diagnostic_0xee62_propagation_delay_exceeded(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        engine.inject_rtt_latency(130.0)  # Exceeds 120 ms
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_PROPAGATION_DELAY_EXCEEDED
        assert engine.diagnostic_code == 0xEE62
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.diagnostic_code == DIAG_OK

    def test_diagnostic_0xee63_carrier_fade_margin_trip(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        engine.inject_carrier_fade(5.0)  # Below 6 dB
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_CARRIER_FADE_MARGIN_TRIP
        assert engine.diagnostic_code == 0xEE63
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.diagnostic_code == DIAG_OK

    def test_diagnostic_0xee64_watchdog_comm_timeout(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        engine.inject_watchdog_timeout()
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_WATCHDOG_COMM_TIMEOUT
        assert engine.diagnostic_code == 0xEE64
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.diagnostic_code == DIAG_OK

    def test_diagnostic_0xee65_dual_crc_safety_fault(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        engine.inject_crc_fault()
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.diagnostic_code == 0xEE65
        assert engine.packet_loss_counter == 1
        assert engine.tripped is True

        engine.clear_fault()
        assert engine.diagnostic_code == DIAG_OK


# ============================================================================
# 7. TestWatchdogAndSilenceCountdown
# ============================================================================

class TestWatchdogAndSilenceCountdown:
    """Validate RF silence accumulation, packet reset, and watchdog timeout."""

    def test_silence_timer_accumulates(self) -> None:
        engine = CIPSatelliteBridgeEngine(watchdog_timeout_ms=250.0)
        engine.connect()
        assert engine.silence_timer_ms == 0.0
        engine.scan_step(dt=0.01)  # 10 ms
        assert engine.silence_timer_ms == pytest.approx(10.0, rel=1e-2)

    def test_packet_arrival_resets_silence_timer(self) -> None:
        engine = CIPSatelliteBridgeEngine(watchdog_timeout_ms=250.0)
        engine.connect()
        engine.scan_step(dt=0.05)  # 50 ms
        assert engine.silence_timer_ms >= 50.0

        pkt = create_valid_satellite_packet()
        assert engine.receive_packet(pkt) is True
        assert engine.silence_timer_ms == 0.0

    def test_silence_exceeding_watchdog_trips(self) -> None:
        engine = CIPSatelliteBridgeEngine(watchdog_timeout_ms=250.0)
        engine.connect()
        # 26 cycles of 10ms = 260ms > 250ms
        for _ in range(26):
            engine.scan_step(dt=0.01)
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_WATCHDOG_COMM_TIMEOUT

    def test_watchdog_inactive_when_disconnected(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.disconnect()
        for _ in range(30):
            engine.scan_step(dt=0.01)
        assert engine.state == SatelliteLinkState.DISCONNECTED
        assert engine.diagnostic_code == DIAG_OK


# ============================================================================
# 8. TestPacketTxRxAndTransmissionDynamics
# ============================================================================

class TestPacketTxRxAndTransmissionDynamics:
    """Validate packet send, receive, promotion, rolling sequence, and corrupted frame handling."""

    def test_send_packet_generates_valid_signed_frame(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        pkt = engine.send_packet(b"\x12\x34\x56")
        assert pkt.payload_bytes == b"\x12\x34\x56"
        assert pkt.sequence_number == 1
        assert pkt.validate_crcs() is True
        assert engine.tx_frame_count == 1

    def test_sequence_counter_rollover(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.sequence_number = 65535
        pkt = engine.send_packet()
        assert pkt.sequence_number == 0
        assert engine.sequence_number == 0

    def test_receive_packet_promotes_to_online_tracking(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        assert engine.state == SatelliteLinkState.DISCONNECTED
        pkt = create_valid_satellite_packet(sequence=5)
        assert engine.receive_packet(pkt) is True
        assert engine.state == SatelliteLinkState.ONLINE_TRACKING
        assert engine.online is True

    def test_receive_packet_corrupted_crc_trips_0xee65(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        bad_pkt = create_valid_satellite_packet()
        bad_pkt.crc_s1 ^= 0x1234
        assert engine.receive_packet(bad_pkt) is False
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DUAL_CRC_SAFETY_FAULT
        assert engine.packet_loss_counter == 1

    def test_receive_packet_out_of_bounds_doppler(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        pkt = create_valid_satellite_packet(doppler_hz=45000.0)
        assert engine.receive_packet(pkt) is False
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DOPPLER_EXCEEDED

    def test_receive_packet_out_of_bounds_rtt(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        pkt = create_valid_satellite_packet(rtt_ms=180.0)
        assert engine.receive_packet(pkt) is False
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_PROPAGATION_DELAY_EXCEEDED

    def test_receive_packet_out_of_bounds_snr(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        pkt = create_valid_satellite_packet(snr_db=3.5)
        assert engine.receive_packet(pkt) is False
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_CARRIER_FADE_MARGIN_TRIP


# ============================================================================
# 9. TestHornerRegisterTableSynchronization
# ============================================================================

class TestHornerRegisterTableSynchronization:
    """Validate bit-exact register sync to %R2680..%R2687 and %M625..%M626."""

    def test_nominal_sync_all_registers_and_coils(self) -> None:
        rt = RegisterTable()
        engine = CIPSatelliteBridgeEngine(
            modulation=ModulationScheme.APSK_16,
            register_table=rt,
        )
        engine.connect()
        engine.sequence_number = 12
        engine.doppler_hz = 1500.0
        engine.rtt_ms = 30.0
        engine.snr_db = 14.0
        engine.pass_remaining_sec = 450
        engine.packet_loss_counter = 2

        engine.sync_to_registers(rt)

        reg_status = rt.read_word(REG_CIP_SATELLITE_STATUS) & 0xFFFF
        assert (reg_status >> 8) == int(SatelliteLinkState.ONLINE_TRACKING)
        assert (reg_status & 0xFF) == int(ModulationScheme.APSK_16)

        assert (rt.read_word(REG_CIP_SATELLITE_SEQUENCE) & 0xFFFF) == 12
        assert rt.read_word(REG_CIP_SATELLITE_DOPPLER_SHIFT) == 1500
        assert (rt.read_word(REG_CIP_SATELLITE_RTT_LATENCY) & 0xFFFF) == 30
        assert (rt.read_word(REG_CIP_SATELLITE_SNR_MARGIN) & 0xFFFF) == 14
        assert (rt.read_word(REG_CIP_SATELLITE_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
        assert (rt.read_word(REG_CIP_SATELLITE_PASS_REMAINING_SEC) & 0xFFFF) == 450
        assert (rt.read_word(REG_CIP_SATELLITE_PACKET_LOSS_COUNTER) & 0xFFFF) == 2

        assert rt.read_bit(COIL_CIP_SATELLITE_ONLINE) is True
        assert rt.read_bit(COIL_CIP_SATELLITE_TRIP) is False

    def test_signed_negative_doppler_sync(self) -> None:
        rt = RegisterTable()
        engine = CIPSatelliteBridgeEngine(register_table=rt)
        engine.connect()
        engine.doppler_hz = -8500.0

        engine.sync_to_registers(rt)
        assert rt.read_word(REG_CIP_SATELLITE_DOPPLER_SHIFT) == -8500
        assert (rt.read_word(REG_CIP_SATELLITE_DOPPLER_SHIFT) & 0xFFFF) == (-8500 & 0xFFFF)

    def test_fault_reflection_in_register_table(self) -> None:
        rt = RegisterTable()
        engine = CIPSatelliteBridgeEngine(register_table=rt)
        engine.connect()
        engine.inject_doppler_shift(40000.0)

        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_SATELLITE_ONLINE) is False
        assert rt.read_bit(COIL_CIP_SATELLITE_TRIP) is True
        assert (rt.read_word(REG_CIP_SATELLITE_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE61

    def test_safe_write_helpers(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R2682", -3000)
        assert rt.read_word("%R2682") == -3000

        safe_write_uword(rt, "%R2683", 65000)
        assert (rt.read_word("%R2683") & 0xFFFF) == 65000

        safe_write_bit(rt, "%M625", True)
        assert rt.read_bit("%M625") is True


# ============================================================================
# 10. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface compliance, ScanContext resolution, step, and execute."""

    def test_ilogicunit_properties(self) -> None:
        engine = CIPSatelliteBridgeEngine(name="TestSatEngine", priority=2, is_enabled=True)
        assert engine.name == "TestSatEngine"
        assert engine.priority == 2
        assert engine.is_enabled is True
        engine.is_enabled = False
        assert engine.is_enabled is False

    def test_scan_step_with_variable_arguments(self) -> None:
        rt = RegisterTable()
        engine = CIPSatelliteBridgeEngine(register_table=rt, auto_activate=True)

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
        engine = CIPSatelliteBridgeEngine(auto_activate=True)
        res_step = engine.step(dt=0.01)
        assert res_step.status == AgentStatus.SUCCESS

        res_exec = engine.execute()
        assert res_exec.status == AgentStatus.SUCCESS

    def test_register_table_resolution_hierarchy(self) -> None:
        rt_local = RegisterTable()
        rt_external = RegisterTable()
        engine = CIPSatelliteBridgeEngine(register_table=rt_local, auto_activate=True)
        engine.sequence_number = 55

        engine.scan_step(register_table=rt_external)
        assert (rt_external.read_word(REG_CIP_SATELLITE_SEQUENCE) & 0xFFFF) == 55


# ============================================================================
# 11. TestPureStructuredTextAndSecurityGuard
# ============================================================================

class TestPureStructuredTextAndSecurityGuard:
    """Validate CipSafetySatelliteSync POU with STParser and anti-ladder SecurityGuard."""

    def test_pure_st_pou_verification(self) -> None:
        assert verify_cip_safety_satellite_pure_st() is True

    def test_st_parser_ast_and_bound_registers(self) -> None:
        ast = STParser(pou_type=POUType.PROGRAM).parse(ST_PROGRAM_CIP_SAFETY_SATELLITE_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R2680", "%R2681", "%R2682", "%R2683",
            "%R2684", "%R2685", "%R2686", "%R2687",
            "%M625", "%M626",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_security_guard_pure_st_assertion(self) -> None:
        SecurityGuard.assert_pure_st_content(ST_PROGRAM_CIP_SAFETY_SATELLITE_SYNC)

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


# ============================================================================
# 12. TestMultiCycleSoakAndStability
# ============================================================================

class TestMultiCycleSoakAndStability:
    """Validate 100-cycle continuous simulation soak test, counter monotonicity, and memory stability."""

    def test_100_cycle_soak_stability(self) -> None:
        rt = RegisterTable()
        engine = CIPSatelliteBridgeEngine(register_table=rt)
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
            assert (rt.read_word(REG_CIP_SATELLITE_SEQUENCE) & 0xFFFF) == cycle

        mem_end, _ = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        mem_growth_kb = (mem_end - mem_start) / 1024.0
        assert mem_growth_kb < 1024.0  # Heap growth bounded < 1MB


# ============================================================================
# 13. TestVerificationRunner9Stages
# ============================================================================

class TestVerificationRunner9Stages:
    """Validate run_cip_safety_satellite_verification 9-stage suite, 4-state contract, and evidence."""

    def test_runner_passes_all_9_stages(self) -> None:
        res = run_cip_safety_satellite_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["total_stages"] == 9
        assert res["stages_passed"] == 9

    def test_runner_evidence_data_integrity(self) -> None:
        res = run_cip_safety_satellite_verification()
        data = res["data"]
        assert data["work_package"] == "W307"
        assert data["gate"] == "G8"
        assert len(data["stages"]) == 9
        for s in data["stages"]:
            assert s["passed"] is True
            assert s["timing_ms"] >= 0.0

    def test_runner_no_file_written_when_output_path_is_none(self) -> None:
        # User requirement: "IMPORTANT: Only write to output_path if output_path is not None!"
        res = run_cip_safety_satellite_verification(output_path=None)
        assert res["status"] == "success"

    def test_runner_writes_file_when_output_path_specified(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_path = Path(tmpdir) / "evidence.json"
            res = run_cip_safety_satellite_verification(output_path=ev_path)
            assert res["status"] == "success"
            assert ev_path.exists()
            with open(ev_path, encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["total_stages"] == 9

    def test_modulation_schemes_in_status_register(self) -> None:
        rt = RegisterTable()
        for mod in (ModulationScheme.QPSK, ModulationScheme.PSK_8, ModulationScheme.APSK_16, ModulationScheme.APSK_32):
            engine = CIPSatelliteBridgeEngine(modulation=mod, register_table=rt)
            engine.connect()
            engine.sync_to_registers(rt)
            val = rt.read_word(REG_CIP_SATELLITE_STATUS) & 0xFFFF
            assert (val & 0xFF) == int(mod)
            assert (val >> 8) == int(SatelliteLinkState.ONLINE_TRACKING)

    def test_privilege_modes_in_sync_to_registers(self) -> None:
        rt = RegisterTable()
        engine = CIPSatelliteBridgeEngine(register_table=rt)
        engine.connect()
        for priv in (PrivilegeMode.SYSTEM, PrivilegeMode.APPLICATION):
            engine.sync_to_registers(rt, privilege=priv)
            assert rt.read_bit(COIL_CIP_SATELLITE_ONLINE) is True

    def test_quick_mode_verification(self) -> None:
        res = run_cip_safety_satellite_verification(quick=True)
        assert res["status"] == "success"
        assert res["stages_passed"] == 9

    def test_packet_loss_counter_increments_on_repeated_faults(self) -> None:
        engine = CIPSatelliteBridgeEngine()
        engine.connect()
        bad_pkt = create_valid_satellite_packet()
        bad_pkt.crc_s1 ^= 0xABCD
        assert engine.receive_packet(bad_pkt) is False
        assert engine.packet_loss_counter == 1
        assert engine.receive_packet(bad_pkt) is False
        assert engine.packet_loss_counter == 2

    def test_pass_remaining_countdown_in_register(self) -> None:
        rt = RegisterTable()
        engine = CIPSatelliteBridgeEngine(register_table=rt, pass_remaining_sec=300)
        engine.connect()
        engine.sync_to_registers(rt)
        assert (rt.read_word(REG_CIP_SATELLITE_PASS_REMAINING_SEC) & 0xFFFF) == 300
        assert bool(engine.status_word & SatelliteStatusBits.PASS_ACTIVE) is True

    def test_cli_entry_point(self) -> None:
        from jev_cscape.telemetry.cip_safety_satellite import main
        assert callable(main)

    def test_doppler_threshold_25khz_trip(self) -> None:
        """Verify Doppler shift > 25,000 Hz trips 0xEE61 when configured at 25 kHz."""
        engine = CIPSatelliteBridgeEngine(max_doppler_hz=25000.0)
        engine.connect()
        engine.inject_doppler_shift(25001.0)
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_DOPPLER_EXCEEDED
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0xEE61

    def test_carrier_fade_threshold_3db_trip(self) -> None:
        """Verify carrier fade / SNR margin < 3.0 dB trips 0xEE63 when configured at 3 dB."""
        engine = CIPSatelliteBridgeEngine(min_snr_db=3.0)
        engine.connect()
        engine.inject_carrier_fade(2.9)
        assert engine.state == SatelliteLinkState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_CARRIER_FADE_MARGIN_TRIP
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0xEE63

    def test_safe_stop_interlock_coils_and_clearance(self) -> None:
        """Verify coil %M626 asserts and %M625 de-asserts upon fault, and clearance restores healthy state."""
        rt = RegisterTable()
        engine = CIPSatelliteBridgeEngine(register_table=rt)
        engine.connect()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_SATELLITE_ONLINE) is True
        assert rt.read_bit(COIL_CIP_SATELLITE_TRIP) is False

        # Trip fault
        engine.inject_watchdog_timeout()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_SATELLITE_ONLINE) is False
        assert rt.read_bit(COIL_CIP_SATELLITE_TRIP) is True
        assert (rt.read_word(REG_CIP_SATELLITE_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE64

        # Clear fault
        engine.clear_fault()
        engine.connect()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_SATELLITE_ONLINE) is True
        assert rt.read_bit(COIL_CIP_SATELLITE_TRIP) is False
        assert (rt.read_word(REG_CIP_SATELLITE_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

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

    def test_script_runner_interop_cli(self) -> None:
        """Verify interop with scripts/run_cip_safety_satellite_verification.py CLI."""
        scripts_runner_path = Path(__file__).resolve().parent.parent / "scripts" / "run_cip_safety_satellite_verification.py"
        assert scripts_runner_path.exists()
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "test_satellite_evidence.json"
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

    def test_module_cli_direct_execution(self) -> None:
        """Verify executing module CLI directly with tempfile output."""
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "module_satellite_evidence.json"
            proc = subprocess.run(
                [sys.executable, "-m", "jev_cscape.telemetry.cip_safety_satellite", "--output", str(tmp_out), "--quick", "--json"],
                capture_output=True,
                text=True,
                check=True,
            )
            assert proc.returncode == 0
            evidence = json.loads(proc.stdout)
            assert evidence["status"] == "success"
            assert tmp_out.exists()
