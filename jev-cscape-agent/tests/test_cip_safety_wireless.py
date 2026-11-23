"""Comprehensive Unit Test Suite for Wave W304 CIP Safety Over Wireless Protocol Engine.

Work Package: W304 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over Wireless (IEEE 802.11ax WiFi 6 / 3GPP 5G URLLC Industrial TSN)

Covers 75+ Deterministic Unit Tests across 12 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnostics: Protocol constants, register mappings (%R2650..%R2657),
   coils (%M618..%M619), diagnostic codes (0x0000, 0xEE51..0xEE55), signed/unsigned 16-bit equality,
   bitwise masking, enums, status bits, and backward-compatibility aliases.
2. TestDualCrcAlgorithmsAndFrameIntegrity: Dual CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B),
   single-bit flip sensitivity, recurrence, EPID CRC32 hashing, CCITT-16, and verify_dual_crc_s helper.
3. TestPacketModelAndBinarySerialization: CIPWirelessSafetyPacket dataclass, inverted header computation,
   CRC generation/validation, binary packing/unpacking bit-exact roundtrip, and corrupted frame rejection.
4. TestEngineInitializationAndStateTransitions: State machine transitions (IDLE -> ASSOCIATING -> CONNECTED_RUNNING -> SAFETY_TRIP),
   auto_activate, associate, connect, disconnect, trip_safety/trip_fault, clear_fault, and reset.
5. TestRfParametersAndSurveillance: Telemetry surveillance for RSSI (-100..0 dBm), SNR (5..45 dB),
   transit latency (us), and jitter (ms), safe operational boundaries, and fault thresholds.
6. TestAllDiagnosticCodesAndFailSafeTrips: Full verification of all 5 diagnostic codes (0xEE51 through 0xEE55),
   immediate de-energization of online status (%M618=False), assertion of trip status (%M619=True),
   and recovery reset for each diagnostic code.
7. TestWatchdogAndSilenceCountdown: RF silence countdown timer accumulation during scan cycles,
   watchdog timeout expiration (> 50.0 ms -> 0xEE54), timer reset on packet arrival, and inactive states.
8. TestPacketTxRxAndTransmissionDynamics: Egress packet transmission with rolling sequence counters,
   ingress packet processing, state promotion, telemetry updates, and CRC corruption fault detection.
9. TestHornerRegisterTableSynchronization: Bit-exact synchronization to Horner OCS registers (%R2650..%R2657)
   and coils (%M618..%M619), signed 16-bit masking `(rt.read_word(...) & 0xFFFF) == expected`,
   negative RSSI representation, and privilege modes.
10. TestILogicUnitCompliance: ILogicUnit interface compliance (scan_step with variable args/kwargs,
    step, execute, reset), ScanContext handling, execution results, and 100-cycle soak memory boundedness.
11. TestPureStructuredTextAndSecurityGuard: Pure IEC 61131-3 ST POU CipSafetyWirelessSync validation
    via STParser and SecurityGuard, AST bound registers, and strict interception of ladder logic
    constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.
12. TestVerificationRunner9Stages: Complete 9-stage verification suite run_cip_safety_wireless_verification,
    strict 4-state engineering contract validation, JSON evidence emission, and script interop.
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
from jev_cscape.telemetry.cip_safety_wireless import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_WIRELESS_CLASS_ID,
    NOMINAL_WIRELESS_RSSI_DBM,
    DEFAULT_RSSI_DBM,
    MIN_RSSI_DBM,
    MAX_RSSI_DBM,
    DEFAULT_RSSI_TRIP_THRESHOLD_DBM,
    WEAK_SIGNAL_THRESHOLD_DBM,
    NOMINAL_SNR_DB,
    DEFAULT_SNR_DB,
    MIN_SNR_DB,
    MAX_SNR_DB,
    MIN_ADEQUATE_SNR_DB,
    NOMINAL_LINK_LATENCY_US,
    DEFAULT_LINK_LATENCY_US,
    DEFAULT_LATENCY_US,
    MIN_LINK_LATENCY_US,
    MAX_LINK_LATENCY_US,
    MAX_ALLOWED_LATENCY_US,
    NOMINAL_JITTER_MS,
    DEFAULT_JITTER_MS,
    DEFAULT_JITTER_TRIP_THRESHOLD_MS,
    JITTER_TRIP_THRESHOLD_MS,
    NOMINAL_RF_WATCHDOG_MS,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    DEFAULT_SAFETY_EPID,
    DEFAULT_EPID,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S_INIT,
    CRC16_CCITT_POLY,
    CRC16_CCITT_INIT,
    REG_CIP_WIRELESS_STATUS,
    REG_CIP_WIRELESS_RSSI_DBM,
    REG_CIP_WIRELESS_SNR_DB,
    REG_CIP_WIRELESS_LATENCY_US,
    REG_CIP_WIRELESS_STATUS_WORD,
    REG_CIP_WIRELESS_DIAGNOSTIC_CODE,
    REG_CIP_WIRELESS_PACKET_LOSS_COUNT,
    REG_CIP_WIRELESS_SEQUENCE_COUNTER,
    COIL_CIP_WIRELESS_ONLINE,
    COIL_CIP_WIRELESS_TRIP,
    REG_WIRELESS_SAFETY_STATE,
    REG_WIRELESS_RSSI_DBM,
    REG_WIRELESS_SNR_DB,
    REG_WIRELESS_LATENCY_MS,
    REG_WIRELESS_STATUS_WORD,
    REG_WIRELESS_DIAGNOSTIC_CODE,
    REG_WIRELESS_PACKET_LOSS_COUNT,
    REG_WIRELESS_SEQUENCE_COUNTER,
    COIL_WIRELESS_SAFETY_LINK_HEALTHY,
    COIL_WIRELESS_SAFETY_STOP_TRIPPED,
    COIL_WIRELESS_ONLINE,
    COIL_WIRELESS_TRIP,
    COIL_WIRELESS_SAFETY_ONLINE,
    COIL_WIRELESS_SAFETY_TRIP,
    DiagnosticCode,
    DIAG_OK,
    DIAG_ERR_PACKET_LOSS,
    DIAG_ERR_WEAK_SIGNAL,
    DIAG_ERR_JITTER_EXCEEDED,
    DIAG_ERR_WATCHDOG_TIMEOUT,
    DIAG_ERR_CRC_FAULT,
    DIAG_PACKET_LOSS,
    DIAG_WEAK_SIGNAL,
    DIAG_JITTER_EXCEEDED,
    DIAG_WATCHDOG_TIMEOUT,
    DIAG_CRC_FAULT,
    DIAG_RSSI_DROP_TRIP,
    DIAG_PACKET_LOSS_TRIP,
    DIAG_LATENCY_EXCEEDED_TRIP,
    DIAG_AUTH_FAIL_TRIP,
    WirelessState,
    WirelessBand,
    WirelessStatusBits,
    CIPWirelessSafetyError,
    WirelessWeakSignalError,
    WirelessJitterExceededError,
    WirelessPacketLossError,
    WirelessWatchdogTimeoutError,
    WirelessCrcFaultError,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    compute_epid_hash,
    calculate_crc16_ccitt,
    verify_dual_crc_s,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CIPWirelessSafetyPacket,
    CipSafetyWirelessPacket,
    create_valid_wireless_packet,
    ST_PROGRAM_CIP_SAFETY_WIRELESS_SYNC,
    CIP_SAFETY_WIRELESS_SYNC_POU,
    CIP_SAFETY_WIRELESS_PURE_ST_POU,
    verify_cip_safety_wireless_pure_st,
    CIPWirelessSafetyEngine,
    CipSafetyWirelessEngine,
    run_cip_safety_wireless_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety constants, registers, diagnostic codes, and enums."""

    def test_class_ids(self) -> None:
        """Verify ODVA CIP Safety Volume 5 Class IDs."""
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_WIRELESS_CLASS_ID == 0x2E

    def test_crc_polynomial_constants(self) -> None:
        """Verify CRC generator polynomials and seed values."""
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC_S_INIT == 0xFFFF
        assert CRC16_CCITT_POLY == 0x1021
        assert CRC16_CCITT_INIT == 0xFFFF

    def test_rf_and_environmental_limits(self) -> None:
        """Verify default limits and trip thresholds for RF surveillance."""
        assert NOMINAL_WIRELESS_RSSI_DBM == -55.0
        assert DEFAULT_RSSI_TRIP_THRESHOLD_DBM == -82.0
        assert WEAK_SIGNAL_THRESHOLD_DBM == -82.0
        assert NOMINAL_SNR_DB == 28.0
        assert MIN_ADEQUATE_SNR_DB == 10.0
        assert NOMINAL_LINK_LATENCY_US == 1200
        assert MAX_ALLOWED_LATENCY_US == 15000
        assert NOMINAL_JITTER_MS == 0.8
        assert DEFAULT_JITTER_TRIP_THRESHOLD_MS == 15.0
        assert NOMINAL_RF_WATCHDOG_MS == 50.0
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 50.0
        assert DEFAULT_SAFETY_EPID == "HORNER-OCS-WIRELESS-SIL3"

    def test_register_and_coil_mappings(self) -> None:
        """Verify Horner OCS register (%R2650..%R2657) and coil (%M618..%M619) addresses."""
        assert REG_CIP_WIRELESS_STATUS == "%R2650"
        assert REG_CIP_WIRELESS_RSSI_DBM == "%R2651"
        assert REG_CIP_WIRELESS_SNR_DB == "%R2652"
        assert REG_CIP_WIRELESS_LATENCY_US == "%R2653"
        assert REG_CIP_WIRELESS_STATUS_WORD == "%R2654"
        assert REG_CIP_WIRELESS_DIAGNOSTIC_CODE == "%R2655"
        assert REG_CIP_WIRELESS_PACKET_LOSS_COUNT == "%R2656"
        assert REG_CIP_WIRELESS_SEQUENCE_COUNTER == "%R2657"
        assert COIL_CIP_WIRELESS_ONLINE == "%M618"
        assert COIL_CIP_WIRELESS_TRIP == "%M619"

    def test_diagnostic_codes_values_and_names(self) -> None:
        """Verify all 5 diagnostic codes (0xEE51 through 0xEE55) plus 0x0000 OK."""
        assert DIAG_OK == 0x0000
        assert DIAG_ERR_PACKET_LOSS == 0xEE51
        assert DIAG_ERR_WEAK_SIGNAL == 0xEE52
        assert DIAG_ERR_JITTER_EXCEEDED == 0xEE53
        assert DIAG_ERR_WATCHDOG_TIMEOUT == 0xEE54
        assert DIAG_ERR_CRC_FAULT == 0xEE55

        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.ERR_PACKET_LOSS == 0xEE51
        assert DiagnosticCode.ERR_WEAK_SIGNAL == 0xEE52
        assert DiagnosticCode.ERR_JITTER_EXCEEDED == 0xEE53
        assert DiagnosticCode.ERR_WATCHDOG_TIMEOUT == 0xEE54
        assert DiagnosticCode.ERR_CRC_FAULT == 0xEE55

    def test_diagnostic_codes_signed_unsigned_equality(self) -> None:
        """Verify signed 16-bit and unsigned 16-bit equality across all diagnostic codes."""
        test_pairs = [
            (DIAG_OK, 0x0000, 0),
            (DIAG_ERR_PACKET_LOSS, 0xEE51, -4527),
            (DIAG_ERR_WEAK_SIGNAL, 0xEE52, -4526),
            (DIAG_ERR_JITTER_EXCEEDED, 0xEE53, -4525),
            (DIAG_ERR_WATCHDOG_TIMEOUT, 0xEE54, -4524),
            (DIAG_ERR_CRC_FAULT, 0xEE55, -4523),
        ]
        for diag_obj, u16, s16 in test_pairs:
            assert diag_obj == u16
            assert diag_obj == s16
            assert (diag_obj & 0xFFFF) == u16
            assert int(diag_obj) == u16 or int(diag_obj) == s16

    def test_diagnostic_code_bitwise_masking_and_hashing(self) -> None:
        """Verify bitwise operations and hashing on DiagnosticCode."""
        diag = DIAG_ERR_WEAK_SIGNAL  # 0xEE52
        assert (diag & 0xFFFF) == 0xEE52
        assert (0xFFFF & diag) == 0xEE52
        assert (diag & 0x00FF) == 0x0052
        assert hash(diag) == hash(0xEE52)
        code_set = {DIAG_ERR_WEAK_SIGNAL, DiagnosticCode(0xEE52), DiagnosticCode(-4526)}
        assert len(code_set) == 1

    def test_diagnostic_code_str_and_repr(self) -> None:
        """Verify string formatting and representation of DiagnosticCode."""
        diag = DIAG_ERR_JITTER_EXCEEDED  # 0xEE53
        assert "0xEE53" in str(diag)
        assert "ERR_JITTER_EXCEEDED" in str(diag)
        assert "DiagnosticCode" in repr(diag)

    def test_wireless_state_enum(self) -> None:
        """Verify WirelessState enum values and transitions."""
        assert WirelessState.IDLE == 0
        assert WirelessState.ASSOCIATING == 1
        assert WirelessState.CONNECTED_RUNNING == 2
        assert WirelessState.SAFETY_TRIP == 3

    def test_wireless_band_enum(self) -> None:
        """Verify WirelessBand frequency band profiles."""
        assert WirelessBand.UNCONFIGURED == 0
        assert WirelessBand.BAND_2_4_GHZ == 1
        assert WirelessBand.BAND_5_GHZ == 2
        assert WirelessBand.WIFI_6_6GHZ == 3
        assert WirelessBand.TSN_5G_URLLC == 4

    def test_wireless_status_bits_enum(self) -> None:
        """Verify WirelessStatusBits bitmask flags for %R2654."""
        assert WirelessStatusBits.ONLINE == 1
        assert WirelessStatusBits.RUNNING == 2
        assert WirelessStatusBits.SAFETY_ACTIVE == 4
        assert WirelessStatusBits.RSSI_GOOD == 8
        assert WirelessStatusBits.SNR_GOOD == 16
        assert WirelessStatusBits.JITTER_GOOD == 32
        assert WirelessStatusBits.TSN_SYNC == 64
        assert WirelessStatusBits.SAFETY_TRIPPED == 128

    def test_aliases_compatibility(self) -> None:
        """Verify aliases for registers, coils, and diagnostic codes."""
        assert REG_WIRELESS_SAFETY_STATE == "%R2650"
        assert REG_WIRELESS_RSSI_DBM == "%R2651"
        assert REG_WIRELESS_SNR_DB == "%R2652"
        assert REG_WIRELESS_LATENCY_MS == "%R2653"
        assert REG_WIRELESS_STATUS_WORD == "%R2654"
        assert REG_WIRELESS_DIAGNOSTIC_CODE == "%R2655"
        assert REG_WIRELESS_PACKET_LOSS_COUNT == "%R2656"
        assert REG_WIRELESS_SEQUENCE_COUNTER == "%R2657"
        assert COIL_WIRELESS_SAFETY_LINK_HEALTHY == "%M618"
        assert COIL_WIRELESS_SAFETY_STOP_TRIPPED == "%M619"
        assert COIL_WIRELESS_ONLINE == "%M618"
        assert COIL_WIRELESS_TRIP == "%M619"
        assert DIAG_PACKET_LOSS == DIAG_ERR_PACKET_LOSS
        assert DIAG_WEAK_SIGNAL == DIAG_ERR_WEAK_SIGNAL
        assert DIAG_JITTER_EXCEEDED == DIAG_ERR_JITTER_EXCEEDED
        assert DIAG_WATCHDOG_TIMEOUT == DIAG_ERR_WATCHDOG_TIMEOUT
        assert DIAG_CRC_FAULT == DIAG_ERR_CRC_FAULT


# ============================================================================
# 2. TestDualCrcAlgorithmsAndFrameIntegrity
# ============================================================================

class TestDualCrcAlgorithmsAndFrameIntegrity:
    """Validate ODVA CIP Safety dual CRCs (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B)."""

    def test_crc_s1_computation_determinism(self) -> None:
        """Verify deterministic calculation of CRC-S1 across repeated invocations."""
        payload = b"\x01\x02\x03\x04\x05\x06"
        c1 = compute_crc_s1(payload)
        c2 = compute_crc_s1(payload)
        assert c1 == c2
        assert 0 <= c1 <= 0xFFFF
        assert calc_crc_s1(payload) == c1

    def test_crc_s2_computation_determinism(self) -> None:
        """Verify deterministic calculation of CRC-S2 across repeated invocations."""
        header = b"\xFE\xFD\xFC\xFB\xFA\xF9"
        c1 = compute_crc_s2(header)
        c2 = compute_crc_s2(header)
        assert c1 == c2
        assert 0 <= c1 <= 0xFFFF
        assert calc_crc_s2(header) == c1

    def test_crc_s1_single_bit_flip_sensitivity(self) -> None:
        """Verify single-bit modification anywhere in payload alters CRC-S1."""
        payload = bytearray(b"\x11\x22\x33\x44\x55\x66")
        original_crc = compute_crc_s1(bytes(payload))

        for byte_idx in range(len(payload)):
            for bit_pos in range(8):
                mutated = bytearray(payload)
                mutated[byte_idx] ^= (1 << bit_pos)
                mutated_crc = compute_crc_s1(bytes(mutated))
                assert mutated_crc != original_crc, (
                    f"Bit flip at byte {byte_idx}, bit {bit_pos} failed to alter CRC-S1!"
                )

    def test_crc_s2_single_bit_flip_sensitivity(self) -> None:
        """Verify single-bit modification anywhere in header alters CRC-S2."""
        header = bytearray(b"\xAA\xBB\xCC\xDD\xEE\xFF")
        original_crc = compute_crc_s2(bytes(header))

        for byte_idx in range(len(header)):
            for bit_pos in range(8):
                mutated = bytearray(header)
                mutated[byte_idx] ^= (1 << bit_pos)
                mutated_crc = compute_crc_s2(bytes(mutated))
                assert mutated_crc != original_crc, (
                    f"Bit flip at byte {byte_idx}, bit {bit_pos} failed to alter CRC-S2!"
                )

    def test_crc_s1_and_s2_are_distinct(self) -> None:
        """Verify CRC-S1 and CRC-S2 use different generator polynomials producing distinct digests."""
        data = b"ODVA CIP Safety Over Wireless Payload Test 123"
        c1 = compute_crc_s1(data)
        c2 = compute_crc_s2(data)
        assert c1 != c2

    def test_epid_hashing_correctness(self) -> None:
        """Verify EPID CRC32 hashing and consistency."""
        epid = "HORNER-OCS-WIRELESS-SIL3"
        h1 = compute_epid_hash(epid)
        h2 = compute_epid_hash(epid)
        assert h1 == h2
        assert 0 <= h1 <= 0xFFFF
        expected = zlib.crc32(epid.encode("utf-8")) & 0xFFFF
        assert h1 == expected

    def test_calculate_crc16_ccitt(self) -> None:
        """Verify compatibility CCITT-16 calculation."""
        data = b"123456789"
        crc = calculate_crc16_ccitt(data)
        assert 0 <= crc <= 0xFFFF

    def test_verify_dual_crc_s_matching_and_failing(self) -> None:
        """Verify verify_dual_crc_s helper function."""
        payload = b"\x01\x02\x03\x04"
        inverted = b"\xFF\xFE\xFD\xFC"
        s1 = compute_crc_s1(payload)
        s2 = compute_crc_s2(inverted)

        assert verify_dual_crc_s(payload, inverted, s1, s2) is True
        assert verify_dual_crc_s(payload, inverted, s1 ^ 0x01, s2) is False
        assert verify_dual_crc_s(payload, inverted, s1, s2 ^ 0x01) is False

    def test_compute_crc_invalid_inputs(self) -> None:
        """Verify ValueError raised when compute_crc functions receive invalid types."""
        with pytest.raises(ValueError):
            compute_crc_s1(12345)  # Not bytes or bytearray
        with pytest.raises(ValueError):
            compute_crc_s2("invalid string")


# ============================================================================
# 3. TestPacketModelAndBinarySerialization
# ============================================================================

class TestPacketModelAndBinarySerialization:
    """Validate CIPWirelessSafetyPacket dataclass and binary serialization."""

    def test_packet_instantiation_defaults(self) -> None:
        """Verify packet default fields and automatic CRC generation."""
        pkt = CIPWirelessSafetyPacket()
        assert pkt.payload == b"\x01\x02\x03\x04"
        assert pkt.sequence_counter == 0
        assert pkt.timestamp_us == 0
        assert pkt.rssi_dbm == NOMINAL_WIRELESS_RSSI_DBM
        assert pkt.snr_db == NOMINAL_SNR_DB
        assert pkt.jitter_ms == NOMINAL_JITTER_MS
        assert pkt.band == WirelessBand.WIFI_6_6GHZ
        assert pkt.crc_s1 != 0
        assert pkt.crc_s2 != 0
        assert pkt.validate_crcs() is True

    def test_packet_custom_initialization(self) -> None:
        """Verify custom payload, sequence counter, and RF parameters."""
        payload = b"\xDE\xAD\xBE\xEF"
        pkt = CIPWirelessSafetyPacket(
            payload=payload,
            sequence_counter=42,
            timestamp_us=5000,
            rssi_dbm=-65.0,
            snr_db=32.0,
            jitter_ms=1.2,
            band=WirelessBand.TSN_5G_URLLC,
        )
        assert pkt.payload == payload
        assert pkt.sequence_counter == 42
        assert pkt.rssi_dbm == -65.0
        assert pkt.validate_crcs() is True

    def test_packet_inverted_header_generation(self) -> None:
        """Verify get_inverted_header returns bitwise NOT of sequence and timestamp."""
        pkt = CIPWirelessSafetyPacket(sequence_counter=0x1234, timestamp_us=0x56789ABC)
        inv = pkt.get_inverted_header()
        assert len(inv) == 6
        expected_raw = (0x1234).to_bytes(2, "big") + (0x56789ABC).to_bytes(4, "big")
        expected_inv = bytes(~b & 0xFF for b in expected_raw)
        assert inv == expected_inv

    def test_packet_crc_computation_and_validation(self) -> None:
        """Verify compute_crcs and validate_crcs functions."""
        pkt = CIPWirelessSafetyPacket(payload=b"SafeTest")
        c1, c2 = pkt.compute_crcs()
        assert pkt.crc_s1 == c1
        assert pkt.crc_s2 == c2
        assert pkt.validate_crcs() is True

    def test_packet_corruption_invalidates_crc(self) -> None:
        """Verify corrupting payload or CRCs causes validate_crcs to return False."""
        pkt = CIPWirelessSafetyPacket(payload=b"SafeTest")
        assert pkt.validate_crcs() is True

        # Corrupt payload
        pkt.payload = b"Hacked!!"
        assert pkt.validate_crcs() is False

        # Restore and corrupt CRC
        pkt.payload = b"SafeTest"
        pkt.compute_crcs()
        pkt.crc_s1 ^= 0x0001
        assert pkt.validate_crcs() is False

    def test_packet_binary_pack_unpack_roundtrip(self) -> None:
        """Verify binary serialization and deserialization bit-exact round-trip."""
        original = CIPWirelessSafetyPacket(
            payload=b"\xCA\xFE\xBA\xBE\x01\x02\x03\x04",
            sequence_counter=1024,
            timestamp_us=123456,
            rssi_dbm=-55.0,
            snr_db=28.0,
            jitter_ms=0.8,
            band=WirelessBand.WIFI_6_6GHZ,
        )
        raw_bytes = original.pack()
        assert isinstance(raw_bytes, bytes)
        assert len(raw_bytes) > 16

        unpacked = CIPWirelessSafetyPacket.unpack(raw_bytes)
        assert unpacked.payload == original.payload
        assert unpacked.sequence_counter == original.sequence_counter
        assert unpacked.timestamp_us == original.timestamp_us
        assert unpacked.rssi_dbm == original.rssi_dbm
        assert unpacked.snr_db == original.snr_db
        assert unpacked.jitter_ms == original.jitter_ms
        assert unpacked.band == original.band
        assert unpacked.crc_s1 == original.crc_s1
        assert unpacked.crc_s2 == original.crc_s2
        assert unpacked.validate_crcs() is True

    def test_packet_unpack_truncated_data_error(self) -> None:
        """Verify unpack raises ValueError on truncated byte sequences."""
        with pytest.raises(ValueError):
            CIPWirelessSafetyPacket.unpack(b"\x00\x01\x02")

    def test_create_valid_wireless_packet_helper(self) -> None:
        """Verify create_valid_wireless_packet factory generates valid packets."""
        pkt = create_valid_wireless_packet(sequence=77, rssi_dbm=-60.0)
        assert pkt.sequence_counter == 77
        assert pkt.rssi_dbm == -60.0
        assert pkt.validate_crcs() is True


# ============================================================================
# 4. TestEngineInitializationAndStateTransitions
# ============================================================================

class TestEngineInitializationAndStateTransitions:
    """Validate CIPWirelessSafetyEngine lifecycle and state transitions."""

    def test_engine_initial_idle_state(self) -> None:
        """Verify initial default engine state is IDLE, offline, untripped."""
        engine = CIPWirelessSafetyEngine(auto_activate=False)
        assert engine.state == WirelessState.IDLE
        assert engine.online is False
        assert engine.is_online is False
        assert engine.link_healthy is False
        assert engine.tripped is False
        assert engine.is_tripped is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.silence_timer_ms == 0.0

    def test_engine_auto_activate_boots_running(self) -> None:
        """Verify auto_activate=True boots directly into CONNECTED_RUNNING."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        assert engine.state == WirelessState.CONNECTED_RUNNING
        assert engine.online is True
        assert engine.tripped is False
        assert engine.diagnostic_code == DIAG_OK

    def test_engine_association_progression(self) -> None:
        """Verify IDLE -> ASSOCIATING state progression."""
        engine = CIPWirelessSafetyEngine(auto_activate=False)
        assert engine.state == WirelessState.IDLE
        engine.associate()
        assert engine.state == WirelessState.ASSOCIATING
        assert engine.online is False
        assert engine.tripped is False

    def test_engine_connect_promotes_to_connected_running(self) -> None:
        """Verify connect() transitions to CONNECTED_RUNNING."""
        engine = CIPWirelessSafetyEngine(auto_activate=False)
        engine.connect()
        assert engine.state == WirelessState.CONNECTED_RUNNING
        assert engine.online is True
        assert engine.tripped is False
        assert engine.diagnostic_code == DIAG_OK

    def test_engine_disconnect_returns_to_idle(self) -> None:
        """Verify disconnect() returns engine to IDLE."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        assert engine.state == WirelessState.CONNECTED_RUNNING
        engine.disconnect()
        assert engine.state == WirelessState.IDLE
        assert engine.online is False

    def test_engine_trip_safety_asserts_safety_trip(self) -> None:
        """Verify trip_safety transitions to SAFETY_TRIP and de-energizes online."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        engine.trip_safety(DIAG_ERR_WEAK_SIGNAL, "Signal too weak")
        assert engine.state == WirelessState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_WEAK_SIGNAL
        assert engine.online is False
        assert engine.tripped is True

    def test_engine_clear_fault_returns_idle(self) -> None:
        """Verify clear_fault() resets error to DIAG_OK and state to IDLE."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        engine.trip_fault(DIAG_ERR_JITTER_EXCEEDED)
        assert engine.tripped is True
        engine.clear_fault()
        assert engine.state == WirelessState.IDLE
        assert engine.diagnostic_code == DIAG_OK
        assert engine.tripped is False

    def test_engine_reset_clears_all_counters(self) -> None:
        """Verify reset() clears faults and zeroes all cumulative counters."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        engine.sequence_counter = 100
        engine.packet_loss_count = 5
        engine.tx_frame_count = 100
        engine.rx_frame_count = 95
        engine.trip_fault(DIAG_ERR_PACKET_LOSS)

        engine.reset()
        assert engine.state == WirelessState.IDLE
        assert engine.diagnostic_code == DIAG_OK
        assert engine.sequence_counter == 0
        assert engine.packet_loss_count == 0
        assert engine.tx_frame_count == 0
        assert engine.rx_frame_count == 0

    def test_engine_status_register_and_word_properties(self) -> None:
        """Verify status_register_value and status_word bit construction."""
        engine = CIPWirelessSafetyEngine(band=WirelessBand.WIFI_6_6GHZ, auto_activate=True)
        reg_val = engine.status_register_value
        high_byte = (reg_val >> 8) & 0xFF
        low_byte = reg_val & 0xFF
        assert high_byte == int(WirelessState.CONNECTED_RUNNING)
        assert low_byte == int(WirelessBand.WIFI_6_6GHZ)

        sw = engine.status_word
        assert (sw & WirelessStatusBits.ONLINE) != 0
        assert (sw & WirelessStatusBits.RUNNING) != 0
        assert (sw & WirelessStatusBits.RSSI_GOOD) != 0
        assert (sw & WirelessStatusBits.SAFETY_TRIPPED) == 0


# ============================================================================
# 5. TestRfParametersAndSurveillance
# ============================================================================

class TestRfParametersAndSurveillance:
    """Validate RF and Black-Channel Telemetry (RSSI, SNR, latency, jitter)."""

    def test_nominal_rf_parameters(self) -> None:
        """Verify nominal RF baseline parameters upon initialization."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        assert engine.rssi_dbm == NOMINAL_WIRELESS_RSSI_DBM
        assert engine.snr_db == NOMINAL_SNR_DB
        assert engine.transit_latency_us == NOMINAL_LINK_LATENCY_US
        assert engine.jitter_ms == NOMINAL_JITTER_MS
        assert engine.packet_loss_count == 0

    def test_safe_rf_parameter_boundaries(self) -> None:
        """Verify healthy operation within allowed boundaries without fault trips."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        valid_pkt = create_valid_wireless_packet(
            rssi_dbm=-65.0,  # > -82 dBm
            snr_db=20.0,     # >= 10 dB
            jitter_ms=5.0,   # <= 15.0 ms
        )
        assert engine.receive_packet(valid_pkt) is True
        assert engine.online is True
        assert engine.tripped is False
        assert engine.diagnostic_code == DIAG_OK

    def test_rssi_weak_signal_detection(self) -> None:
        """Verify RSSI degradation below threshold (< -82 dBm) trips DIAG_ERR_WEAK_SIGNAL (0xEE52)."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        engine.inject_weak_signal(rssi_dbm=-86.0)
        assert engine.state == WirelessState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_WEAK_SIGNAL
        assert engine.diagnostic_code == 0xEE52
        assert engine.online is False
        assert engine.tripped is True

    def test_rssi_packet_arrival_below_threshold_trips(self) -> None:
        """Verify ingress frame carrying low RSSI triggers safety trip."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        weak_pkt = create_valid_wireless_packet(rssi_dbm=-88.0)
        res = engine.receive_packet(weak_pkt)
        assert res is False
        assert engine.state == WirelessState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_WEAK_SIGNAL

    def test_snr_adequate_and_inadequate_status_bit(self) -> None:
        """Verify SNR_GOOD bit in status word reflects SNR level."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        assert (engine.status_word & WirelessStatusBits.SNR_GOOD) != 0

        engine.snr_db = 8.0  # < 10 dB
        assert (engine.status_word & WirelessStatusBits.SNR_GOOD) == 0

    def test_latency_tracking_and_timestamp_update(self) -> None:
        """Verify transit latency updates upon receiving packets."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        pkt = create_valid_wireless_packet(timestamp_us=3500)
        engine.receive_packet(pkt)
        assert engine.transit_latency_us == 3500

    def test_jitter_monitoring_nominal(self) -> None:
        """Verify nominal jitter (0.8 ms) does not trip engine."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        pkt = create_valid_wireless_packet(jitter_ms=2.5)
        assert engine.receive_packet(pkt) is True
        assert engine.jitter_ms == 2.5
        assert engine.tripped is False

    def test_jitter_exceeded_trips_fault(self) -> None:
        """Verify jitter > 15.0 ms trips DIAG_ERR_JITTER_EXCEEDED (0xEE53)."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        engine.inject_jitter_exceeded(jitter_ms=19.2)
        assert engine.state == WirelessState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_JITTER_EXCEEDED
        assert engine.diagnostic_code == 0xEE53
        assert engine.online is False
        assert engine.tripped is True


# ============================================================================
# 6. TestAllDiagnosticCodesAndFailSafeTrips
# ============================================================================

class TestAllDiagnosticCodesAndFailSafeTrips:
    """Validate all diagnostic codes (0xEE51 through 0xEE55) and fail-safe trip de-energization."""

    def test_diagnostic_code_0xee51_packet_loss_trip_de_energizes(self) -> None:
        """Verify DIAG_ERR_PACKET_LOSS (0xEE51) trips fail-safe state and de-energizes online."""
        rt = RegisterTable()
        engine = CIPWirelessSafetyEngine(register_table=rt, auto_activate=True)
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_CIP_WIRELESS_ONLINE) is True
        assert rt.read_bit(COIL_CIP_WIRELESS_TRIP) is False

        # Inject packet loss trip
        engine.inject_packet_loss(dropped_count=15)
        engine.sync_to_registers(rt)

        assert engine.state == WirelessState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_PACKET_LOSS
        assert (engine.diagnostic_code & 0xFFFF) == 0xEE51
        assert engine.online is False
        assert engine.tripped is True
        # Coil verification
        assert rt.read_bit(COIL_CIP_WIRELESS_ONLINE) is False
        assert rt.read_bit(COIL_CIP_WIRELESS_TRIP) is True
        assert (rt.read_word(REG_CIP_WIRELESS_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE51

    def test_diagnostic_code_0xee52_weak_signal_trip_de_energizes(self) -> None:
        """Verify DIAG_ERR_WEAK_SIGNAL (0xEE52) trips fail-safe state and de-energizes online."""
        rt = RegisterTable()
        engine = CIPWirelessSafetyEngine(register_table=rt, auto_activate=True)
        engine.inject_weak_signal(rssi_dbm=-90.0)
        engine.sync_to_registers(rt)

        assert engine.state == WirelessState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_WEAK_SIGNAL
        assert (engine.diagnostic_code & 0xFFFF) == 0xEE52
        assert rt.read_bit(COIL_CIP_WIRELESS_ONLINE) is False
        assert rt.read_bit(COIL_CIP_WIRELESS_TRIP) is True
        assert (rt.read_word(REG_CIP_WIRELESS_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE52

    def test_diagnostic_code_0xee53_jitter_exceeded_trip_de_energizes(self) -> None:
        """Verify DIAG_ERR_JITTER_EXCEEDED (0xEE53) trips fail-safe state and de-energizes online."""
        rt = RegisterTable()
        engine = CIPWirelessSafetyEngine(register_table=rt, auto_activate=True)
        engine.inject_jitter_exceeded(jitter_ms=22.0)
        engine.sync_to_registers(rt)

        assert engine.state == WirelessState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_JITTER_EXCEEDED
        assert (engine.diagnostic_code & 0xFFFF) == 0xEE53
        assert rt.read_bit(COIL_CIP_WIRELESS_ONLINE) is False
        assert rt.read_bit(COIL_CIP_WIRELESS_TRIP) is True
        assert (rt.read_word(REG_CIP_WIRELESS_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE53

    def test_diagnostic_code_0xee54_watchdog_timeout_trip_de_energizes(self) -> None:
        """Verify DIAG_ERR_WATCHDOG_TIMEOUT (0xEE54) trips fail-safe state and de-energizes online."""
        rt = RegisterTable()
        engine = CIPWirelessSafetyEngine(register_table=rt, auto_activate=True)
        engine.inject_watchdog_timeout()
        engine.sync_to_registers(rt)

        assert engine.state == WirelessState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_WATCHDOG_TIMEOUT
        assert (engine.diagnostic_code & 0xFFFF) == 0xEE54
        assert rt.read_bit(COIL_CIP_WIRELESS_ONLINE) is False
        assert rt.read_bit(COIL_CIP_WIRELESS_TRIP) is True
        assert (rt.read_word(REG_CIP_WIRELESS_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE54

    def test_diagnostic_code_0xee55_crc_fault_trip_de_energizes(self) -> None:
        """Verify DIAG_ERR_CRC_FAULT (0xEE55) trips fail-safe state and de-energizes online."""
        rt = RegisterTable()
        engine = CIPWirelessSafetyEngine(register_table=rt, auto_activate=True)
        engine.inject_crc_fault()
        engine.sync_to_registers(rt)

        assert engine.state == WirelessState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_CRC_FAULT
        assert (engine.diagnostic_code & 0xFFFF) == 0xEE55
        assert rt.read_bit(COIL_CIP_WIRELESS_ONLINE) is False
        assert rt.read_bit(COIL_CIP_WIRELESS_TRIP) is True
        assert (rt.read_word(REG_CIP_WIRELESS_DIAGNOSTIC_CODE) & 0xFFFF) == 0xEE55

    def test_recovery_from_each_diagnostic_code(self) -> None:
        """Verify clean recovery reset from each of the 5 diagnostic codes."""
        codes = [
            DIAG_ERR_PACKET_LOSS,
            DIAG_ERR_WEAK_SIGNAL,
            DIAG_ERR_JITTER_EXCEEDED,
            DIAG_ERR_WATCHDOG_TIMEOUT,
            DIAG_ERR_CRC_FAULT,
        ]
        rt = RegisterTable()
        engine = CIPWirelessSafetyEngine(register_table=rt, auto_activate=True)

        for code in codes:
            engine.trip_fault(code)
            assert engine.tripped is True
            assert engine.diagnostic_code == code

            # Clear and verify reset to healthy
            engine.clear_fault()
            assert engine.tripped is False
            assert engine.diagnostic_code == DIAG_OK
            assert engine.state == WirelessState.IDLE

    def test_multiple_fault_injections_sequence(self) -> None:
        """Verify sequence of multiple fault injections and recovery."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        engine.inject_weak_signal(-88.0)
        assert engine.diagnostic_code == 0xEE52

        engine.clear_fault()
        engine.connect()
        engine.inject_jitter_exceeded(25.0)
        assert engine.diagnostic_code == 0xEE53


# ============================================================================
# 7. TestWatchdogAndSilenceCountdown
# ============================================================================

class TestWatchdogAndSilenceCountdown:
    """Validate RF silence watchdog countdown and timeout tripping (0xEE54)."""

    def test_watchdog_silence_timer_accumulates_in_scan_step(self) -> None:
        """Verify silence timer increases by dt_ms on each scan_step."""
        engine = CIPWirelessSafetyEngine(watchdog_timeout_ms=50.0, auto_activate=True)
        assert engine.silence_timer_ms == 0.0

        engine.scan_step(dt=0.01)  # 10ms
        assert engine.silence_timer_ms == pytest.approx(10.0)

        engine.scan_step(dt=0.01)  # 20ms
        assert engine.silence_timer_ms == pytest.approx(20.0)

    def test_packet_reception_resets_silence_timer(self) -> None:
        """Verify receiving a valid packet resets the silence timer to zero."""
        engine = CIPWirelessSafetyEngine(watchdog_timeout_ms=50.0, auto_activate=True)
        engine.scan_step(dt=0.01)
        engine.scan_step(dt=0.01)
        assert engine.silence_timer_ms == pytest.approx(20.0)

        pkt = create_valid_wireless_packet()
        engine.receive_packet(pkt)
        assert engine.silence_timer_ms == 0.0

    def test_silence_exceeding_watchdog_trips_0xee54(self) -> None:
        """Verify silence exceeding watchdog timeout threshold trips 0xEE54."""
        engine = CIPWirelessSafetyEngine(watchdog_timeout_ms=50.0, auto_activate=True)

        # 6 steps x 10ms = 60ms > 50ms
        for _ in range(6):
            engine.scan_step(dt=0.01)

        assert engine.state == WirelessState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_WATCHDOG_TIMEOUT
        assert (engine.diagnostic_code & 0xFFFF) == 0xEE54
        assert engine.online is False
        assert engine.tripped is True

    def test_watchdog_inactive_when_idle_or_tripped(self) -> None:
        """Verify silence timer does not increment when engine is IDLE."""
        engine = CIPWirelessSafetyEngine(auto_activate=False)
        assert engine.state == WirelessState.IDLE
        engine.scan_step(dt=0.01)
        assert engine.silence_timer_ms == 0.0

    def test_injected_watchdog_timeout(self) -> None:
        """Verify inject_watchdog_timeout() immediately forces 0xEE54 trip."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        engine.inject_watchdog_timeout()
        assert engine.state == WirelessState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_WATCHDOG_TIMEOUT

    def test_scan_step_when_already_tripped(self) -> None:
        """Verify scan_step behaves stably when already in SAFETY_TRIP."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        engine.trip_fault(DIAG_ERR_WEAK_SIGNAL)
        res = engine.scan_step(dt=0.01)
        assert res.status == AgentStatus.SUCCESS
        assert engine.diagnostic_code == DIAG_ERR_WEAK_SIGNAL


# ============================================================================
# 8. TestPacketTxRxAndTransmissionDynamics
# ============================================================================

class TestPacketTxRxAndTransmissionDynamics:
    """Validate frame transmission, reception, and protocol dynamics."""

    def test_transmit_packet_generates_valid_frame(self) -> None:
        """Verify transmit_packet constructs a valid, signed frame."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        pkt = engine.transmit_packet(b"\x12\x34\x56\x78")
        assert pkt.payload == b"\x12\x34\x56\x78"
        assert pkt.validate_crcs() is True
        assert pkt.crc_s1 != 0
        assert pkt.crc_s2 != 0

    def test_transmit_packet_increments_sequence_and_tx_count(self) -> None:
        """Verify sequence counter and tx_frame_count advance with each transmission."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        assert engine.sequence_counter == 0
        assert engine.tx_frame_count == 0

        p1 = engine.transmit_packet()
        assert engine.sequence_counter == 1
        assert engine.tx_frame_count == 1
        assert p1.sequence_counter == 1

        p2 = engine.transmit_packet()
        assert engine.sequence_counter == 2
        assert engine.tx_frame_count == 2
        assert p2.sequence_counter == 2

    def test_sequence_counter_rollover_at_65535(self) -> None:
        """Verify sequence counter rolls over from 65535 to 0 cleanly."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        engine.sequence_counter = 65535
        p = engine.transmit_packet()
        assert engine.sequence_counter == 0
        assert p.sequence_counter == 0

    def test_receive_packet_valid_updates_telemetry(self) -> None:
        """Verify receive_packet updates engine telemetry and frame counters."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        assert engine.rx_frame_count == 0

        pkt = create_valid_wireless_packet(
            rssi_dbm=-62.0,
            snr_db=30.0,
            jitter_ms=1.1,
            timestamp_us=4000,
        )
        ok = engine.receive_packet(pkt)
        assert ok is True
        assert engine.rx_frame_count == 1
        assert engine.rssi_dbm == -62.0
        assert engine.snr_db == 30.0
        assert engine.jitter_ms == 1.1
        assert engine.transit_latency_us == 4000

    def test_receive_packet_promotes_associating_to_running(self) -> None:
        """Verify valid frame receipt promotes ASSOCIATING to CONNECTED_RUNNING."""
        engine = CIPWirelessSafetyEngine(auto_activate=False)
        engine.associate()
        assert engine.state == WirelessState.ASSOCIATING

        pkt = create_valid_wireless_packet()
        ok = engine.receive_packet(pkt)
        assert ok is True
        assert engine.state == WirelessState.CONNECTED_RUNNING
        assert engine.online is True

    def test_receive_packet_corrupted_crc_trips_0xee55(self) -> None:
        """Verify corrupted frame CRC causes rejection and trips DIAG_ERR_CRC_FAULT (0xEE55)."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        pkt = create_valid_wireless_packet()
        pkt.crc_s1 ^= 0x00FF  # Tamper CRC

        ok = engine.receive_packet(pkt)
        assert ok is False
        assert engine.state == WirelessState.SAFETY_TRIP
        assert engine.diagnostic_code == DIAG_ERR_CRC_FAULT
        assert (engine.diagnostic_code & 0xFFFF) == 0xEE55
        assert engine.tripped is True
        assert engine.online is False


# ============================================================================
# 9. TestHornerRegisterTableSynchronization
# ============================================================================

class TestHornerRegisterTableSynchronization:
    """Validate bit-exact synchronization to Horner OCS registers and signed masking."""

    def test_nominal_sync_all_registers_and_coils(self) -> None:
        """Verify bit-exact mapping into %R2650..%R2657 and %M618..%M619."""
        rt = RegisterTable()
        engine = CIPWirelessSafetyEngine(band=WirelessBand.WIFI_6_6GHZ, register_table=rt, auto_activate=True)
        engine.sync_to_registers(rt)

        # %R2650: High byte = State (2), Low byte = Band (3)
        expected_status = (int(WirelessState.CONNECTED_RUNNING) << 8) | int(WirelessBand.WIFI_6_6GHZ)
        assert (rt.read_word(REG_CIP_WIRELESS_STATUS) & 0xFFFF) == expected_status

        # %R2651: RSSI = -55 dBm
        assert rt.read_word(REG_CIP_WIRELESS_RSSI_DBM) == -55
        assert (rt.read_word(REG_CIP_WIRELESS_RSSI_DBM) & 0xFFFF) == ((-55) & 0xFFFF)

        # %R2652: SNR = 28 dB
        assert rt.read_word(REG_CIP_WIRELESS_SNR_DB) == 28

        # %R2653: Latency = 1200 us
        assert (rt.read_word(REG_CIP_WIRELESS_LATENCY_US) & 0xFFFF) == 1200

        # %R2655: Diagnostic Code = 0x0000
        assert (rt.read_word(REG_CIP_WIRELESS_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000

        # %R2656: Loss count = 0
        assert (rt.read_word(REG_CIP_WIRELESS_PACKET_LOSS_COUNT) & 0xFFFF) == 0

        # %R2657: Sequence counter = 0
        assert (rt.read_word(REG_CIP_WIRELESS_SEQUENCE_COUNTER) & 0xFFFF) == 0

        # Coils %M618..%M619
        assert rt.read_bit(COIL_CIP_WIRELESS_ONLINE) is True
        assert rt.read_bit(COIL_CIP_WIRELESS_TRIP) is False

    def test_signed_16bit_masking_all_registers(self) -> None:
        """Verify strict signed 16-bit masking `(rt.read_word(...) & 0xFFFF) == expected`."""
        rt = RegisterTable()
        engine = CIPWirelessSafetyEngine(register_table=rt, auto_activate=True)
        engine.sequence_counter = 45000
        engine.packet_loss_count = 12
        engine.sync_to_registers(rt)

        assert (rt.read_word("%R2650") & 0xFFFF) == engine.status_register_value
        assert (rt.read_word("%R2651") & 0xFFFF) == (int(round(engine.rssi_dbm)) & 0xFFFF)
        assert (rt.read_word("%R2652") & 0xFFFF) == int(round(engine.snr_db))
        assert (rt.read_word("%R2653") & 0xFFFF) == engine.transit_latency_us
        assert (rt.read_word("%R2654") & 0xFFFF) == engine.status_word
        assert (rt.read_word("%R2655") & 0xFFFF) == (int(engine.diagnostic_code) & 0xFFFF)
        assert (rt.read_word("%R2656") & 0xFFFF) == 12
        assert (rt.read_word("%R2657") & 0xFFFF) == 45000

    def test_negative_rssi_signed_read_and_masking(self) -> None:
        """Verify negative RSSI (-55 dBm) reads as -55 signed and 0xFFC9 masked."""
        rt = RegisterTable()
        engine = CIPWirelessSafetyEngine(register_table=rt, auto_activate=True)
        engine.rssi_dbm = -55.0
        engine.sync_to_registers(rt)

        signed_read = rt.read_word(REG_CIP_WIRELESS_RSSI_DBM)
        assert signed_read == -55
        assert (signed_read & 0xFFFF) == 0xFFC9
        assert (signed_read & 0xFFFF) == ((-55) & 0xFFFF)

    def test_fault_reflection_in_register_space(self) -> None:
        """Verify all 5 trip codes reflect exact bit patterns in %R2655 and coil %M619."""
        codes = [
            (DIAG_ERR_PACKET_LOSS, 0xEE51, -4527),
            (DIAG_ERR_WEAK_SIGNAL, 0xEE52, -4526),
            (DIAG_ERR_JITTER_EXCEEDED, 0xEE53, -4525),
            (DIAG_ERR_WATCHDOG_TIMEOUT, 0xEE54, -4524),
            (DIAG_ERR_CRC_FAULT, 0xEE55, -4523),
        ]
        rt = RegisterTable()
        engine = CIPWirelessSafetyEngine(register_table=rt, auto_activate=True)

        for diag, u16, s16 in codes:
            engine.trip_fault(diag)
            engine.sync_to_registers(rt)

            assert rt.read_bit(COIL_CIP_WIRELESS_ONLINE) is False
            assert rt.read_bit(COIL_CIP_WIRELESS_TRIP) is True
            assert (rt.read_word(REG_CIP_WIRELESS_DIAGNOSTIC_CODE) & 0xFFFF) == u16
            assert rt.read_word(REG_CIP_WIRELESS_DIAGNOSTIC_CODE) == s16

    def test_privilege_modes_in_sync(self) -> None:
        """Verify sync_to_registers executes cleanly under SYSTEM and USER privileges."""
        rt = RegisterTable()
        engine = CIPWirelessSafetyEngine(register_table=rt, auto_activate=True)
        engine.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_bit(COIL_CIP_WIRELESS_ONLINE) is True

        engine.sync_to_registers(rt, privilege=PrivilegeMode.USER)
        assert rt.read_bit(COIL_CIP_WIRELESS_ONLINE) is True

    def test_safe_write_helpers(self) -> None:
        """Verify safe_write_word, safe_write_uword, and safe_write_bit helpers."""
        rt = RegisterTable()
        safe_write_word(rt, "%R2651", -75)
        assert rt.read_word("%R2651") == -75
        assert (rt.read_word("%R2651") & 0xFFFF) == ((-75) & 0xFFFF)

        safe_write_uword(rt, "%R2655", 0xEE51)
        assert (rt.read_word("%R2655") & 0xFFFF) == 0xEE51

        safe_write_bit(rt, "%M618", True)
        assert rt.read_bit("%M618") is True
        safe_write_bit(rt, "%M618", False)
        assert rt.read_bit("%M618") is False


# ============================================================================
# 10. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface compliance and scan simulation."""

    def test_ilogicunit_properties(self) -> None:
        """Verify ILogicUnit contract properties: name, priority, is_enabled."""
        engine = CIPWirelessSafetyEngine(name="CustomWirelessEngine", priority=5)
        assert engine.name == "CustomWirelessEngine"
        assert engine.priority == 5
        assert engine.is_enabled is True
        engine.is_enabled = False
        assert engine.is_enabled is False

    def test_scan_step_with_args_and_kwargs(self) -> None:
        """Verify scan_step accepts positional dt, kwargs dt, dt_ms, and context."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)

        # Float positional dt in seconds
        r1 = engine.scan_step(0.010)
        assert r1.status == AgentStatus.SUCCESS

        # Float keyword dt
        r2 = engine.scan_step(dt=0.010)
        assert r2.status == AgentStatus.SUCCESS

        # Integer keyword dt_ms
        r3 = engine.scan_step(dt_ms=10.0)
        assert r3.status == AgentStatus.SUCCESS

    def test_step_alias_method(self) -> None:
        """Verify step() delegates to scan_step."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        res = engine.step(dt=0.01)
        assert res.status == AgentStatus.SUCCESS

    def test_execute_scan_context_method(self) -> None:
        """Verify execute(context) complies with scan Phase 2 execution."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        ctx = ScanContext(cycle_number=1, dt_s=0.010)
        res = engine.execute(context=ctx)
        assert res.status == AgentStatus.SUCCESS

    def test_scan_step_returns_success_execution_result(self) -> None:
        """Verify scan_step returns ExecutionResult with detailed data payload."""
        engine = CIPWirelessSafetyEngine(auto_activate=True)
        res = engine.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert "state" in res.data
        assert "diagnostic_code" in res.data
        assert "online" in res.data

    def test_register_table_resolution_hierarchy(self) -> None:
        """Verify target table resolution priority from context, kwargs, or instance."""
        rt_inst = RegisterTable()
        rt_ctx = RegisterTable()
        engine = CIPWirelessSafetyEngine(register_table=rt_inst, auto_activate=True)

        # Context takes priority
        ctx = ScanContext(cycle_number=1, dt_s=0.01)
        ctx.register_table = rt_ctx
        engine.scan_step(context=ctx)
        assert rt_ctx.read_bit(COIL_CIP_WIRELESS_ONLINE) is True

    def test_100_cycle_soak_stability_and_zero_memory_leak(self) -> None:
        """Verify 100-cycle continuous simulation with bounded memory footprint."""
        rt = RegisterTable()
        engine = CIPWirelessSafetyEngine(register_table=rt, auto_activate=True)

        tracemalloc.start()
        mem_start, _ = tracemalloc.get_traced_memory()

        for cycle in range(1, 101):
            tx_pkt = engine.transmit_packet()
            rx_pkt = create_valid_wireless_packet(sequence=cycle)
            engine.receive_packet(rx_pkt)
            res = engine.scan_step(dt=0.01, register_table=rt)
            assert res.status == AgentStatus.SUCCESS
            assert engine.online is True
            assert engine.tripped is False

        mem_end, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        growth_kb = (mem_end - mem_start) / 1024.0
        assert growth_kb < 1024.0  # Heap growth must be < 1 MB
        assert engine.tx_frame_count == 100
        assert engine.rx_frame_count == 100


# ============================================================================
# 11. TestPureStructuredTextAndSecurityGuard
# ============================================================================

class TestPureStructuredTextAndSecurityGuard:
    """Validate pure IEC 61131-3 Structured Text POU and anti-ladder security enforcement."""

    def test_pure_st_pou_verification(self) -> None:
        """Verify pure ST POU validation passes via verify_cip_safety_wireless_pure_st."""
        assert verify_cip_safety_wireless_pure_st() is True

    def test_st_parser_ast_and_bound_registers(self) -> None:
        """Verify STParser parses CipSafetyWirelessSync POU and binds all required registers."""
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_WIRELESS_SYNC_POU)
        ast = STParser(pou_type=POUType.PROGRAM).parse(CIP_SAFETY_WIRELESS_SYNC_POU)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "CipSafetyWirelessSync"

        expected_registers = {
            "%R2650", "%R2651", "%R2652", "%R2653",
            "%R2654", "%R2655", "%R2656", "%R2657",
            "%M618", "%M619",
        }
        assert expected_registers.issubset(set(ast.bound_registers))

    @pytest.mark.parametrize("contact_snippet", [
        "PROGRAM LadderTest VAR c : BOOL; END_VAR ---[ ]--- c; END_PROGRAM",
        "PROGRAM LadderTest VAR c : BOOL; END_VAR ---[/]--- c; END_PROGRAM",
    ])
    def test_anti_ladder_contacts_rejection(self, contact_snippet: str) -> None:
        """Verify ladder contacts are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(contact_snippet)

    @pytest.mark.parametrize("coil_snippet", [
        "PROGRAM LadderTest VAR c : BOOL; END_VAR ---( )--- c; END_PROGRAM",
        "PROGRAM LadderTest VAR c : BOOL; END_VAR ---(S)--- c; END_PROGRAM",
        "PROGRAM LadderTest VAR c : BOOL; END_VAR ---(R)--- c; END_PROGRAM",
    ])
    def test_anti_ladder_coils_rejection(self, coil_snippet: str) -> None:
        """Verify ladder coils are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(coil_snippet)

    @pytest.mark.parametrize("delimiters", [
        "PROGRAM LadderTest RUNG 1 END_PROGRAM",
        "PROGRAM LadderTest NETWORK 10 END_PROGRAM",
    ])
    def test_anti_ladder_rungs_and_networks_rejection(self, delimiters: str) -> None:
        """Verify RUNG and NETWORK delimiters are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(delimiters)

    @pytest.mark.parametrize("mnemonics", [
        "PROGRAM LadderTest XIC(StartSwitch); END_PROGRAM",
        "PROGRAM LadderTest OTE(MotorCoil); END_PROGRAM",
    ])
    def test_anti_ladder_mnemonics_rejection(self, mnemonics: str) -> None:
        """Verify ladder mnemonics (XIC, OTE) are rejected with LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(mnemonics)

    def test_security_guard_pure_st_content_assertion(self) -> None:
        """Verify SecurityGuard approves legitimate Structured Text without ladder constructs."""
        clean_code = "PROGRAM Clean VAR a: INT; END_VAR a := 1 + 2; END_PROGRAM"
        SecurityGuard.assert_pure_st_content(clean_code)


# ============================================================================
# 12. TestVerificationRunner9Stages
# ============================================================================

class TestVerificationRunner9Stages:
    """Validate deterministic 9-stage verification runner and strict 4-state contract."""

    def test_runner_runs_and_passes_all_9_stages(self) -> None:
        """Verify run_cip_safety_wireless_verification executes all 9 stages successfully."""
        res = run_cip_safety_wireless_verification()
        assert isinstance(res, dict)
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["stages_passed"] == 9
        assert res["total_stages"] == 9
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9

    def test_runner_returns_strict_4_state_success(self) -> None:
        """Verify runner conforms strictly to 4-state contract ('success')."""
        res = run_cip_safety_wireless_verification()
        assert res["status"] in ("success", "failed", "blocked", "inconclusive")
        assert res["status"] == "success"
        assert "All 9 Industrial ODVA CIP Safety Over Wireless" in res["details"]

    def test_runner_evidence_data_integrity(self) -> None:
        """Verify metadata in evidence payload."""
        res = run_cip_safety_wireless_verification()
        data = res["data"]
        assert data["gate"] == "G8"
        assert data["work_package"] == "W304"
        assert "%R2650..%R2657" in data["registers"]
        assert "%M618..%M619" in data["registers"]

        stages = data["stages"]
        assert len(stages) == 9
        for s in stages:
            assert s["passed"] is True
            assert s["timing_ms"] >= 0.0

    def test_runner_file_emission_to_disk(self) -> None:
        """Verify evidence JSON file is emitted to disk and valid."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            res = run_cip_safety_wireless_verification(output_path=tmp_path)
            assert tmp_path.exists()
            assert tmp_path.stat().st_size > 0
            with open(tmp_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["stages_passed"] == 9
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def test_script_runner_interop(self) -> None:
        """Verify interop with scripts/run_cip_safety_wireless_verification.py CLI."""
        scripts_runner_path = Path(__file__).resolve().parent.parent / "scripts" / "run_cip_safety_wireless_verification.py"
        assert scripts_runner_path.exists()
        import subprocess
        import sys
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_out = Path(tmpdir) / "test_wireless_evidence.json"
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
