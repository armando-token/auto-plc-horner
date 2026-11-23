"""Comprehensive Unit Test Suite for Wave W268 CIP Safety Over Wi-Fi 6 Protocol Engine.

Work Package: W268 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Wireless Dual-Antenna Diversity (IEEE 802.11ax / Industrial Wi-Fi 6) for Horner OCS.

Covers Comprehensive Deterministic Unit Tests across 12 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit values, string representations,
   bitwise operations, hashing, enums, register names, coil addresses, and class IDs.
2. TestDualCrcAndOfdmaFrameIntegrity: CRC-S1 (0x5935), CRC-S2 (0x755B), dual CRC verification, diversified sequence
   counters (~seq & 0xFFFF), OFDMA frame serialization, MRC power math, and single-bit mutation corruption detection.
3. TestStateTransitions: Progression across WiFi6SafetyState (IDLE -> BSS_ASSOCIATING -> SECURITY_HANDSHAKE -> SAFE_OPERATIONAL -> SAFE_STOP_TRIPPED),
   connect, disconnect, roaming state transitions, and recovery resets.
4. TestRssiDegradationTrip: RF RSSI surveillance, dual-antenna diversity threshold monitoring (-75 dBm configured
   threshold & -82 dBm default threshold), trip 0xEE61 when both antennas degrade, coil %M535 assertion, and recovery reset.
5. TestPacketErrorRateBurstTrip: Scaled packet error rate surveillance (0.01% units), nominal tracking (12 -> 0.12%),
   burst trip (> 5.00% / 500 scaled -> 0xEE62), EPI silence watchdog timeout (15000 us -> 0xEE62), coil %M535 assertion, and reset.
6. TestRoamingTimeoutFault: IEEE 802.11r Fast BSS Transition surveillance, roaming timer accumulation, roaming timeout
   watchdog trip (> 50.0 ms -> 0xEE63), roaming event counter (%R2295) increment, coil %M535 assertion, and recovery reset.
7. TestDiversityAntennaFault: Dual-antenna spatial diversity monitoring, antenna disconnection / severe delta detection
   (<= -85 dBm or >= 30 dB delta -> 0xEE64), antenna switching hysteresis (2 dB), coil %M535 assertion, and recovery reset.
8. TestRegisterSynchronization: %R2290..%R2297 and %M534..%M535 bit-exact synchronization, PrivilegeMode.SYSTEM,
   fault reflection, safe write wrappers (safe_write_word, safe_write_uword, safe_write_bit).
9. TestPureSTAndSecurity: STParser & SecurityGuard verification of CipSafetyWiFi6Sync POU, AST variable memory_address
   and bound registers validation (%R2290..%R2297, %M534..%M535).
10. TestAntiLadderConstructRejection: Rejection of ladder logic constructs (contacts, coils, rungs, networks, mnemonics)
    with LadderForbiddenError.
11. TestILogicUnitComplianceAndSoak: ILogicUnit interface compliance (scan_step, step, execute, reset),
    properties validation, 100-cycle continuous soak simulation, and heap boundedness (< 100 KB growth).
12. TestExceptionsAndVerificationRunner: Exception inheritance hierarchy, 10-stage runner execution,
    strict 4-state contract validation, and evidence emission.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import struct
import tempfile
import time
import tracemalloc
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_wifi6 import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_WIRELESS_CLASS_ID,
    CIP_SAFETY_WIFI6_CLASS_ID,
    NOMINAL_CIP_SAFETY_WIFI6_LINK_STATE,
    DEFAULT_LINK_STATE,
    NOMINAL_CIP_SAFETY_WIFI6_RSSI_PRIMARY_DBM,
    DEFAULT_RSSI_PRIMARY_DBM,
    MIN_RSSI_DBM,
    MAX_RSSI_DBM,
    DEFAULT_RSSI_TRIP_THRESHOLD_DBM,
    NOMINAL_CIP_SAFETY_WIFI6_RSSI_DIVERSITY_DBM,
    DEFAULT_RSSI_DIVERSITY_DBM,
    DEFAULT_DIVERSITY_FAULT_THRESHOLD_DBM,
    DEFAULT_MAX_ANTENNA_DELTA_DB,
    DEFAULT_DIVERSITY_HYSTERESIS_DB,
    NOMINAL_CIP_SAFETY_WIFI6_PER_SCALED,
    DEFAULT_PER_SCALED,
    DEFAULT_PER_TRIP_THRESHOLD_SCALED,
    NOMINAL_CIP_SAFETY_WIFI6_TX_FRAME_COUNT,
    DEFAULT_TX_FRAME_COUNT,
    NOMINAL_CIP_SAFETY_WIFI6_ROAMING_EVENT_COUNT,
    DEFAULT_ROAMING_EVENT_COUNT,
    DEFAULT_ROAMING_TIMEOUT_MS,
    NOMINAL_CIP_SAFETY_WIFI6_EPI_TIMER_US,
    DEFAULT_EPI_TIMER_US,
    DEFAULT_EPI_US,
    DEFAULT_EPI_TIMEOUT_THRESHOLD_US,
    NOMINAL_CIP_SAFETY_WIFI6_DIAGNOSTIC_CODE,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CIP_SAFETY_CRC_INIT,
    CRC_S_INIT,
    REG_CIP_SAFETY_WIFI6_LINK_STATE,
    REG_CIP_SAFETY_WIFI6_RSSI_PRIMARY_DBM,
    REG_CIP_SAFETY_WIFI6_RSSI_DIVERSITY_DBM,
    REG_CIP_SAFETY_WIFI6_PER_SCALED,
    REG_CIP_SAFETY_WIFI6_TX_FRAME_COUNT,
    REG_CIP_SAFETY_WIFI6_ROAMING_EVENT_COUNT,
    REG_CIP_SAFETY_WIFI6_EPI_TIMER_US,
    REG_CIP_SAFETY_WIFI6_DIAGNOSTIC_CODE,
    COIL_CIP_SAFETY_WIFI6_OPERATIONAL,
    COIL_CIP_SAFETY_WIFI6_TRIPPED,
    REG_WIFI6_LINK_STATE,
    REG_WIFI6_SAFETY_STATE,
    REG_WIFI6_STATE,
    REG_CIP_SAFETY_WIFI6_STATE,
    REG_WIFI6_RSSI_PRIMARY_DBM,
    REG_WIFI6_RSSI_PRIMARY,
    REG_CIP_WIFI6_RSSI_PRIMARY,
    REG_WIFI6_RSSI_DIVERSITY_DBM,
    REG_WIFI6_RSSI_DIVERSITY,
    REG_CIP_WIFI6_RSSI_DIVERSITY,
    REG_WIFI6_PER_SCALED,
    REG_WIFI6_PER,
    REG_CIP_WIFI6_PER_SCALED,
    REG_WIFI6_TX_FRAME_COUNT,
    REG_WIFI6_TX_COUNT,
    REG_WIFI6_TX_FRAMES,
    REG_CIP_WIFI6_TX_FRAMES,
    REG_WIFI6_ROAMING_EVENT_COUNT,
    REG_WIFI6_ROAMING_COUNT,
    REG_WIFI6_ROAMS,
    REG_CIP_WIFI6_ROAMS,
    REG_WIFI6_EPI_TIMER_US,
    REG_WIFI6_EPI_TIMER,
    REG_WIFI6_EPI_US,
    REG_CIP_WIFI6_EPI_US,
    REG_WIFI6_DIAGNOSTIC_CODE,
    REG_WIFI6_DIAGNOSTIC_STATUS_CODE,
    REG_WIFI6_DIAG_CODE,
    REG_CIP_SAFETY_WIFI6_DIAG_CODE,
    REG_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    COIL_WIFI6_OPERATIONAL,
    COIL_WIFI6_SAFETY_OPERATIONAL,
    COIL_WIFI6_LINK_HEALTHY,
    COIL_CIP_SAFETY_WIFI6_HEALTHY,
    COIL_SAFETY_OPERATIONAL,
    COIL_SAFETY_LINK_HEALTHY,
    COIL_WIFI6_TRIPPED,
    COIL_WIFI6_SAFETY_TRIPPED,
    COIL_WIFI6_SAFE_STOP_TRIPPED,
    COIL_CIP_SAFETY_WIFI6_STOP_TRIPPED,
    COIL_SAFETY_TRIPPED,
    COIL_SAFETY_STOP_TRIPPED,
    COIL_SAFE_STOP_TRIPPED,
    DiagnosticCode,
    DIAG_OK,
    DIAG_RSSI_DEGRADATION_TRIP,
    DIAG_PACKET_ERROR_BURST_TRIP,
    DIAG_BSS_ROAM_TIMEOUT_FAULT,
    DIAG_DIVERSITY_ANTENNA_FAULT,
    DiagnosticStatusCode,
    WiFi6DiagnosticCode,
    CIPSafetyWiFi6DiagnosticCode,
    WiFi6SafetyState,
    CIPSafetyWiFi6State,
    CipWiFi6SafetyState,
    SafeWiFi6State,
    AntennaSelection,
    DiversityMode,
    CIPWiFi6SafetyError,
    WiFi6RssiDegradationError,
    WiFi6PacketErrorBurstError,
    WiFi6BssRoamTimeoutError,
    WiFi6DiversityAntennaError,
    CIP_SAFETY_WIFI6_PURE_ST_POU,
    CIP_SAFETY_WIFI6_SYNC_POU,
    CIP_SAFETY_WIFI6_POU,
    PURE_ST_POU,
    CipSafetyWiFi6Sync,
    CipSafetyWiFi6SyncPOU,
    verify_cip_safety_wifi6_pure_st,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    calculate_mrc_rssi,
    calculate_diversity_gain,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CIPWiFi6SafetyPacket,
    CIPWiFi6SafetyFrame,
    CIPSafetyWiFi6Packet,
    CIPSafetyWiFi6Frame,
    WiFi6SafetyPacket,
    WiFi6SafetyFrame,
    create_valid_wifi6_packet,
    CIPSafetyWiFi6Engine,
    CipSafetyWiFi6Engine,
    CIPSafetyWifi6Engine,
    CIPWiFi6SafetyEngine,
    WiFi6SafetyEngine,
    CIP_SAFETY_WIFI6_ENGINE,
    run_cip_safety_wifi6_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety Over Wi-Fi 6 protocol constants, class IDs, enums, and diagnostic codes."""

    def test_class_ids_and_protocol_constants(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_WIRELESS_CLASS_ID == 0x2E
        assert CIP_SAFETY_WIFI6_CLASS_ID == 0x2E

        assert NOMINAL_CIP_SAFETY_WIFI6_LINK_STATE == 3
        assert DEFAULT_LINK_STATE == 3

        assert NOMINAL_CIP_SAFETY_WIFI6_RSSI_PRIMARY_DBM == -54
        assert DEFAULT_RSSI_PRIMARY_DBM == -54
        assert MIN_RSSI_DBM == -100
        assert MAX_RSSI_DBM == 0
        assert DEFAULT_RSSI_TRIP_THRESHOLD_DBM == -82

        assert NOMINAL_CIP_SAFETY_WIFI6_RSSI_DIVERSITY_DBM == -58
        assert DEFAULT_RSSI_DIVERSITY_DBM == -58
        assert DEFAULT_DIVERSITY_FAULT_THRESHOLD_DBM == -85
        assert DEFAULT_MAX_ANTENNA_DELTA_DB == 30
        assert DEFAULT_DIVERSITY_HYSTERESIS_DB == 2

        assert NOMINAL_CIP_SAFETY_WIFI6_PER_SCALED == 12
        assert DEFAULT_PER_SCALED == 12
        assert DEFAULT_PER_TRIP_THRESHOLD_SCALED == 500

        assert NOMINAL_CIP_SAFETY_WIFI6_TX_FRAME_COUNT == 100
        assert DEFAULT_TX_FRAME_COUNT == 100

        assert NOMINAL_CIP_SAFETY_WIFI6_ROAMING_EVENT_COUNT == 0
        assert DEFAULT_ROAMING_EVENT_COUNT == 0
        assert DEFAULT_ROAMING_TIMEOUT_MS == 50.0

        assert NOMINAL_CIP_SAFETY_WIFI6_EPI_TIMER_US == 5000
        assert DEFAULT_EPI_TIMER_US == 5000
        assert DEFAULT_EPI_US == 5000
        assert DEFAULT_EPI_TIMEOUT_THRESHOLD_US == 15000

        assert NOMINAL_CIP_SAFETY_WIFI6_DIAGNOSTIC_CODE == 0x0000

    def test_crc_polynomial_constants(self) -> None:
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC_S_INIT == 0xFFFF

    def test_canonical_register_and_coil_mappings(self) -> None:
        assert REG_CIP_SAFETY_WIFI6_LINK_STATE == "%R2290"
        assert REG_CIP_SAFETY_WIFI6_RSSI_PRIMARY_DBM == "%R2291"
        assert REG_CIP_SAFETY_WIFI6_RSSI_DIVERSITY_DBM == "%R2292"
        assert REG_CIP_SAFETY_WIFI6_PER_SCALED == "%R2293"
        assert REG_CIP_SAFETY_WIFI6_TX_FRAME_COUNT == "%R2294"
        assert REG_CIP_SAFETY_WIFI6_ROAMING_EVENT_COUNT == "%R2295"
        assert REG_CIP_SAFETY_WIFI6_EPI_TIMER_US == "%R2296"
        assert REG_CIP_SAFETY_WIFI6_DIAGNOSTIC_CODE == "%R2297"

        assert COIL_CIP_SAFETY_WIFI6_OPERATIONAL == "%M534"
        assert COIL_CIP_SAFETY_WIFI6_TRIPPED == "%M535"

    def test_register_and_coil_aliases(self) -> None:
        assert REG_WIFI6_LINK_STATE == "%R2290"
        assert REG_WIFI6_SAFETY_STATE == "%R2290"
        assert REG_WIFI6_STATE == "%R2290"
        assert REG_CIP_SAFETY_WIFI6_STATE == "%R2290"

        assert REG_WIFI6_RSSI_PRIMARY_DBM == "%R2291"
        assert REG_WIFI6_RSSI_PRIMARY == "%R2291"
        assert REG_CIP_WIFI6_RSSI_PRIMARY == "%R2291"

        assert REG_WIFI6_RSSI_DIVERSITY_DBM == "%R2292"
        assert REG_WIFI6_RSSI_DIVERSITY == "%R2292"
        assert REG_CIP_WIFI6_RSSI_DIVERSITY == "%R2292"

        assert REG_WIFI6_PER_SCALED == "%R2293"
        assert REG_WIFI6_PER == "%R2293"
        assert REG_CIP_WIFI6_PER_SCALED == "%R2293"

        assert REG_WIFI6_TX_FRAME_COUNT == "%R2294"
        assert REG_WIFI6_TX_COUNT == "%R2294"
        assert REG_WIFI6_TX_FRAMES == "%R2294"
        assert REG_CIP_WIFI6_TX_FRAMES == "%R2294"

        assert REG_WIFI6_ROAMING_EVENT_COUNT == "%R2295"
        assert REG_WIFI6_ROAMING_COUNT == "%R2295"
        assert REG_WIFI6_ROAMS == "%R2295"
        assert REG_CIP_WIFI6_ROAMS == "%R2295"

        assert REG_WIFI6_EPI_TIMER_US == "%R2296"
        assert REG_WIFI6_EPI_TIMER == "%R2296"
        assert REG_WIFI6_EPI_US == "%R2296"
        assert REG_CIP_WIFI6_EPI_US == "%R2296"

        assert REG_WIFI6_DIAGNOSTIC_CODE == "%R2297"
        assert REG_WIFI6_DIAGNOSTIC_STATUS_CODE == "%R2297"
        assert REG_WIFI6_DIAG_CODE == "%R2297"
        assert REG_CIP_SAFETY_WIFI6_DIAG_CODE == "%R2297"
        assert REG_DIAGNOSTIC_CODE == "%R2297"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2297"

        assert COIL_WIFI6_OPERATIONAL == "%M534"
        assert COIL_WIFI6_SAFETY_OPERATIONAL == "%M534"
        assert COIL_WIFI6_LINK_HEALTHY == "%M534"
        assert COIL_CIP_SAFETY_WIFI6_HEALTHY == "%M534"
        assert COIL_SAFETY_OPERATIONAL == "%M534"
        assert COIL_SAFETY_LINK_HEALTHY == "%M534"

        assert COIL_WIFI6_TRIPPED == "%M535"
        assert COIL_WIFI6_SAFETY_TRIPPED == "%M535"
        assert COIL_WIFI6_SAFE_STOP_TRIPPED == "%M535"
        assert COIL_CIP_SAFETY_WIFI6_STOP_TRIPPED == "%M535"
        assert COIL_SAFETY_TRIPPED == "%M535"
        assert COIL_SAFETY_STOP_TRIPPED == "%M535"
        assert COIL_SAFE_STOP_TRIPPED == "%M535"

    def test_diagnostic_code_values_and_signed_representations(self) -> None:
        # 0x0000 OK
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.OK == 0
        assert int(DiagnosticCode.OK) == 0x0000
        assert (DiagnosticCode.OK & 0xFFFF) == 0x0000

        # 0xEE61 RSSI_DEGRADATION_TRIP (-4511 in signed 16-bit)
        assert DiagnosticCode.RSSI_DEGRADATION_TRIP == 0xEE61
        assert DiagnosticCode.RSSI_DEGRADATION_TRIP == (0xEE61 - 0x10000)
        assert DiagnosticCode.RSSI_DEGRADATION_TRIP == -4511
        assert (DiagnosticCode.RSSI_DEGRADATION_TRIP & 0xFFFF) == 0xEE61

        # 0xEE62 PACKET_ERROR_BURST_TRIP (-4510 in signed 16-bit)
        assert DiagnosticCode.PACKET_ERROR_BURST_TRIP == 0xEE62
        assert DiagnosticCode.PACKET_ERROR_BURST_TRIP == (0xEE62 - 0x10000)
        assert DiagnosticCode.PACKET_ERROR_BURST_TRIP == -4510
        assert (DiagnosticCode.PACKET_ERROR_BURST_TRIP & 0xFFFF) == 0xEE62

        # 0xEE63 BSS_ROAM_TIMEOUT_FAULT (-4509 in signed 16-bit)
        assert DiagnosticCode.BSS_ROAM_TIMEOUT_FAULT == 0xEE63
        assert DiagnosticCode.BSS_ROAM_TIMEOUT_FAULT == (0xEE63 - 0x10000)
        assert DiagnosticCode.BSS_ROAM_TIMEOUT_FAULT == -4509
        assert (DiagnosticCode.BSS_ROAM_TIMEOUT_FAULT & 0xFFFF) == 0xEE63

        # 0xEE64 DIVERSITY_ANTENNA_FAULT (-4508 in signed 16-bit)
        assert DiagnosticCode.DIVERSITY_ANTENNA_FAULT == 0xEE64
        assert DiagnosticCode.DIVERSITY_ANTENNA_FAULT == (0xEE64 - 0x10000)
        assert DiagnosticCode.DIVERSITY_ANTENNA_FAULT == -4508
        assert (DiagnosticCode.DIVERSITY_ANTENNA_FAULT & 0xFFFF) == 0xEE64

    def test_diagnostic_code_string_and_repr_representations(self) -> None:
        c_ok = DiagnosticCode.OK
        assert "0x0000" in str(c_ok)
        assert "OK" in str(c_ok)
        assert "DiagnosticCode.OK" in repr(c_ok)

        c_rssi = DiagnosticCode.RSSI_DEGRADATION_TRIP
        assert "0xEE61" in str(c_rssi)
        assert "RSSI_DEGRADATION_TRIP" in str(c_rssi)
        assert "DiagnosticCode.RSSI_DEGRADATION_TRIP" in repr(c_rssi)

        c_per = DiagnosticCode.PACKET_ERROR_BURST_TRIP
        assert "0xEE62" in str(c_per)
        assert "PACKET_ERROR_BURST_TRIP" in str(c_per)
        assert "DiagnosticCode.PACKET_ERROR_BURST_TRIP" in repr(c_per)

        c_roam = DiagnosticCode.BSS_ROAM_TIMEOUT_FAULT
        assert "0xEE63" in str(c_roam)
        assert "BSS_ROAM_TIMEOUT_FAULT" in str(c_roam)
        assert "DiagnosticCode.BSS_ROAM_TIMEOUT_FAULT" in repr(c_roam)

        c_div = DiagnosticCode.DIVERSITY_ANTENNA_FAULT
        assert "0xEE64" in str(c_div)
        assert "DIVERSITY_ANTENNA_FAULT" in str(c_div)
        assert "DiagnosticCode.DIVERSITY_ANTENNA_FAULT" in repr(c_div)

    def test_diagnostic_code_bitwise_operations_and_hashing(self) -> None:
        c1 = DiagnosticCode.RSSI_DEGRADATION_TRIP      # 0xEE61
        c2 = DiagnosticCode.DIVERSITY_ANTENNA_FAULT     # 0xEE64

        # Bitwise AND
        res_and = c1 & 0xFF00
        assert isinstance(res_and, DiagnosticCode)
        assert res_and == 0xEE00

        res_rand = 0x00FF & c1
        assert isinstance(res_rand, DiagnosticCode)
        assert res_rand == 0x0061

        # Bitwise OR
        res_or = c1 | 0x000F
        assert isinstance(res_or, DiagnosticCode)
        assert res_or == 0xEE6F

        # Bitwise XOR
        res_xor = c1 ^ 0x0001
        assert isinstance(res_xor, DiagnosticCode)
        assert res_xor == 0xEE60

        # Hashing and deduplication in sets
        code_set = {c1, c2, DiagnosticCode(0xEE61), DiagnosticCode(-4511)}
        assert len(code_set) == 2
        assert c1 in code_set
        assert c2 in code_set
        assert DiagnosticCode(-4508) in code_set

        # Module-level aliases
        assert DIAG_OK is DiagnosticCode.OK
        assert DIAG_RSSI_DEGRADATION_TRIP is DiagnosticCode.RSSI_DEGRADATION_TRIP
        assert DIAG_PACKET_ERROR_BURST_TRIP is DiagnosticCode.PACKET_ERROR_BURST_TRIP
        assert DIAG_BSS_ROAM_TIMEOUT_FAULT is DiagnosticCode.BSS_ROAM_TIMEOUT_FAULT
        assert DIAG_DIVERSITY_ANTENNA_FAULT is DiagnosticCode.DIVERSITY_ANTENNA_FAULT

        assert DiagnosticStatusCode is DiagnosticCode
        assert WiFi6DiagnosticCode is DiagnosticCode
        assert CIPSafetyWiFi6DiagnosticCode is DiagnosticCode

    def test_diagnostic_code_properties_and_non_int_comparison(self) -> None:
        c = DiagnosticCode.RSSI_DEGRADATION_TRIP
        assert c.value == 0xEE61
        assert int(c) == 0xEE61
        assert (c & 0xFFFF) == 0xEE61

        # Non-integer comparison
        assert (c == "arbitrary_string") is False
        assert (c != "arbitrary_string") is True
        assert (c == 3.14) is False

    def test_wifi6_safety_state_enum_and_aliases(self) -> None:
        assert WiFi6SafetyState.IDLE == 0
        assert WiFi6SafetyState.BSS_ASSOCIATING == 1
        assert WiFi6SafetyState.SECURITY_HANDSHAKE == 2
        assert WiFi6SafetyState.SAFE_OPERATIONAL == 3
        assert WiFi6SafetyState.SAFE_STOP_TRIPPED == 4

        # Camel-case aliases
        assert WiFi6SafetyState.Idle == 0
        assert WiFi6SafetyState.BssAssociating == 1
        assert WiFi6SafetyState.SecurityHandshake == 2
        assert WiFi6SafetyState.SafeOperational == 3
        assert WiFi6SafetyState.SafeStopTripped == 4

        # Common aliases
        assert WiFi6SafetyState.OPERATIONAL == 3
        assert WiFi6SafetyState.SAFE_STOP == 4
        assert WiFi6SafetyState.TRIPPED == 4

        # Type aliases
        assert CIPSafetyWiFi6State is WiFi6SafetyState
        assert CipWiFi6SafetyState is WiFi6SafetyState
        assert SafeWiFi6State is WiFi6SafetyState

    def test_antenna_selection_and_diversity_mode_enums(self) -> None:
        assert AntennaSelection.PRIMARY == 0
        assert AntennaSelection.DIVERSITY == 1
        assert AntennaSelection.MRC_COMBINED == 2
        assert AntennaSelection.ANTENNA_PRIMARY == 0
        assert AntennaSelection.ANTENNA_DIVERSITY == 1

        assert DiversityMode.SELECTION_DIVERSITY == 0
        assert DiversityMode.MAXIMAL_RATIO_COMBINING == 1
        assert DiversityMode.SELECTION == 0
        assert DiversityMode.MRC == 1


# ============================================================================
# 2. TestDualCrcAndOfdmaFrameIntegrity
# ============================================================================

class TestDualCrcAndOfdmaFrameIntegrity:
    """Validate dual CRC-S1/S2 checksum computation, OFDMA frame serialization, MRC power math, and corruption detection."""

    def test_crc_s1_and_crc_s2_polynomials(self) -> None:
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        crc1 = compute_crc_s1(data)
        crc2 = compute_crc_s2(data)

        assert isinstance(crc1, int)
        assert isinstance(crc2, int)
        assert 0 <= crc1 <= 0xFFFF
        assert 0 <= crc2 <= 0xFFFF
        assert crc1 != crc2
        assert calc_crc_s1(data) == crc1
        assert calc_crc_s2(data) == crc2

    def test_crc_functions_variadic_args_and_errors(self) -> None:
        # Multiple byte chunks concatenation
        crc1 = compute_crc_s1(b"\x01\x02", b"\x03\x04")
        crc2 = compute_crc_s2(b"\x01\x02", b"\x03\x04")
        assert crc1 == compute_crc_s1(b"\x01\x02\x03\x04")
        assert crc2 == compute_crc_s2(b"\x01\x02\x03\x04")

        # Invalid arguments raise ValueError
        with pytest.raises(ValueError, match="Unsupported arguments to compute_crc_s1"):
            compute_crc_s1(12345)
        with pytest.raises(ValueError, match="Unsupported arguments to compute_crc_s2"):
            compute_crc_s2("invalid_str")

    def test_valid_packet_generation_and_crc_verification(self) -> None:
        pkt = create_valid_wifi6_packet(
            sequence_primary=100,
            rssi_primary_dbm=-54,
            rssi_diversity_dbm=-58,
            per_scaled=12,
            epi_timer_us=5000,
            payload=b"\x10\x20\x30\x40",
        )

        assert pkt.sequence_primary == 100
        assert pkt.sequence_diversified == (~100) & 0xFFFF
        assert pkt.verify_sequence() is True
        assert pkt.verify_crcs() is True
        assert pkt.crc_s1 > 0
        assert pkt.crc_s2 > 0

    def test_diversified_sequence_inversion_and_failure(self) -> None:
        pkt = create_valid_wifi6_packet(sequence_primary=250)
        assert pkt.verify_sequence() is True

        # Corrupt diversified sequence
        pkt.sequence_diversified = 9999
        assert pkt.verify_sequence() is False

    def test_payload_single_bit_mutation_detection(self) -> None:
        pkt = create_valid_wifi6_packet(sequence_primary=42, payload=b"\xAA\xBB\xCC\xDD")
        assert pkt.verify_crcs() is True

        # Mutate single bit in payload
        pkt.mutate_bit(byte_offset=1, bit_pos=3)
        assert pkt.verify_crcs() is False

    def test_mrc_power_math_and_diversity_gain(self) -> None:
        # Case 1: Identical signals (-54 dBm on both antennas)
        # Power sum doubles -> +3.01 dB gain
        mrc_rssi = calculate_mrc_rssi(-54.0, -54.0)
        gain = calculate_diversity_gain(-54.0, -54.0)
        assert pytest.approx(-50.99, abs=0.15) == mrc_rssi
        assert pytest.approx(3.01, abs=0.15) == gain

        # Case 2: One dominant antenna (-50 dBm vs -80 dBm)
        # Power sum essentially equal to stronger signal -> near 0 dB gain
        mrc_dominant = calculate_mrc_rssi(-50.0, -80.0)
        gain_dominant = calculate_diversity_gain(-50.0, -80.0)
        assert pytest.approx(-50.0, abs=0.1) == mrc_dominant
        assert gain_dominant < 0.1

    def test_packet_type_aliases(self) -> None:
        assert CIPWiFi6SafetyFrame is CIPWiFi6SafetyPacket
        assert CIPSafetyWiFi6Packet is CIPWiFi6SafetyPacket
        assert CIPSafetyWiFi6Frame is CIPWiFi6SafetyPacket
        assert WiFi6SafetyPacket is CIPWiFi6SafetyPacket
        assert WiFi6SafetyFrame is CIPWiFi6SafetyPacket


# ============================================================================
# 3. TestStateTransitions
# ============================================================================

class TestStateTransitions:
    """Validate Wi-Fi 6 Safe Communication State Machine transitions and reset behaviors."""

    def test_initial_state_auto_activate_true_vs_false(self) -> None:
        rt_auto = RegisterTable()
        engine_auto = CIPSafetyWiFi6Engine(register_table=rt_auto, auto_activate=True)
        assert engine_auto.state == WiFi6SafetyState.SAFE_OPERATIONAL
        assert engine_auto.is_healthy is True
        assert engine_auto.is_safe_stop_tripped is False
        assert rt_auto.read_word("%R2290") == 3
        assert rt_auto.read_bit("%M534") is True
        assert rt_auto.read_bit("%M535") is False

        rt_idle = RegisterTable()
        engine_idle = CIPSafetyWiFi6Engine(register_table=rt_idle, auto_activate=False)
        assert engine_idle.state == WiFi6SafetyState.IDLE
        assert engine_idle.is_healthy is False
        assert engine_idle.is_safe_stop_tripped is True
        assert rt_idle.read_word("%R2290") == 0
        assert rt_idle.read_bit("%M534") is False
        assert rt_idle.read_bit("%M535") is True

    def test_step_by_step_state_progression(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=False)

        # IDLE (0)
        assert engine.state == WiFi6SafetyState.IDLE
        assert rt.read_word("%R2290") == 0
        assert rt.read_bit("%M534") is False
        assert rt.read_bit("%M535") is True

        # Transition to BSS_ASSOCIATING (1)
        engine.state = WiFi6SafetyState.BSS_ASSOCIATING
        engine.sync_to_registers(rt)
        assert engine.state == WiFi6SafetyState.BSS_ASSOCIATING
        assert rt.read_word("%R2290") == 1
        assert rt.read_bit("%M534") is False

        # Transition to SECURITY_HANDSHAKE (2)
        engine.state = WiFi6SafetyState.SECURITY_HANDSHAKE
        engine.sync_to_registers(rt)
        assert engine.state == WiFi6SafetyState.SECURITY_HANDSHAKE
        assert rt.read_word("%R2290") == 2
        assert rt.read_bit("%M534") is False

        # Transition to SAFE_OPERATIONAL (3)
        engine.state = WiFi6SafetyState.SAFE_OPERATIONAL
        engine.sync_to_registers(rt)
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL
        assert rt.read_word("%R2290") == 3
        assert rt.read_bit("%M534") is True
        assert rt.read_bit("%M535") is False

        # Fault trip to SAFE_STOP_TRIPPED (4)
        engine.trip_fault(DiagnosticCode.RSSI_DEGRADATION_TRIP)
        assert engine.state == WiFi6SafetyState.SAFE_STOP_TRIPPED
        assert rt.read_word("%R2290") == 4
        assert rt.read_uword("%R2297") == 0xEE61
        assert rt.read_bit("%M534") is False
        assert rt.read_bit("%M535") is True

    def test_associate_and_connect_method(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=False)
        assert engine.state == WiFi6SafetyState.IDLE

        result = engine.associate_and_connect()
        assert result is True
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert rt.read_word("%R2290") == 3
        assert rt.read_bit("%M534") is True
        assert rt.read_bit("%M535") is False

    def test_disconnect_method(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL

        engine.disconnect()
        assert engine.state == WiFi6SafetyState.IDLE
        assert rt.read_word("%R2290") == 0
        assert rt.read_bit("%M534") is False
        assert rt.read_bit("%M535") is True

    def test_operator_and_fault_reset_recovery(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)

        engine.trip_fault(DiagnosticCode.PACKET_ERROR_BURST_TRIP)
        assert engine.state == WiFi6SafetyState.SAFE_STOP_TRIPPED
        assert engine.is_safe_stop_tripped is True

        engine.reset()
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_healthy is True
        assert engine.is_safe_stop_tripped is False
        assert rt.read_word("%R2290") == 3
        assert rt.read_uword("%R2297") == 0x0000
        assert rt.read_bit("%M534") is True
        assert rt.read_bit("%M535") is False

        # Verify aliases operator_reset and fault_reset
        engine.trip_fault(DiagnosticCode.BSS_ROAM_TIMEOUT_FAULT)
        engine.operator_reset()
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL

        engine.trip_fault(DiagnosticCode.DIVERSITY_ANTENNA_FAULT)
        engine.fault_reset()
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL


# ============================================================================
# 4. TestRssiDegradationTrip
# ============================================================================

class TestRssiDegradationTrip:
    """Validate RF RSSI degradation trip (0xEE61) when primary and diversity RSSI drop below safe threshold (-75 dBm & -82 dBm)."""

    def test_rssi_degradation_trip_below_custom_75_dbm_threshold(self) -> None:
        rt = RegisterTable()
        # Configure engine with -75 dBm threshold
        engine = CIPSafetyWiFi6Engine(
            register_table=rt,
            auto_activate=True,
            rssi_trip_threshold_dbm=-75,
        )

        # Both antennas fall below -75 dBm: Primary = -76 dBm, Diversity = -78 dBm -> TRIPS!
        safe = engine.evaluate_antenna_diversity(rssi_primary=-76, rssi_diversity=-78)
        assert safe is False
        assert engine.state == WiFi6SafetyState.SAFE_STOP_TRIPPED
        assert engine.diagnostic_code == DiagnosticCode.RSSI_DEGRADATION_TRIP
        assert engine.diagnostic_code == 0xEE61
        assert engine.diagnostic_code == -4511
        assert engine.is_safe_stop_tripped is True
        assert engine.is_healthy is False

        # Register reflection
        assert rt.read_word("%R2290") == 4
        assert rt.read_word("%R2291") == -76
        assert rt.read_word("%R2292") == -78
        assert rt.read_uword("%R2297") == 0xEE61
        assert rt.read_bit("%M534") is False
        assert rt.read_bit("%M535") is True

    def test_diversity_protection_prevents_trip_when_one_antenna_healthy(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(
            register_table=rt,
            auto_activate=True,
            rssi_trip_threshold_dbm=-75,
        )

        # Primary is degraded to -80 dBm (< -75 dBm), but Diversity is healthy at -70 dBm (>= -75 dBm)
        safe = engine.evaluate_antenna_diversity(rssi_primary=-80, rssi_diversity=-70)
        assert safe is True
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.active_antenna == AntennaSelection.DIVERSITY
        assert rt.read_word("%R2290") == 3
        assert rt.read_uword("%R2297") == 0x0000
        assert rt.read_bit("%M534") is True
        assert rt.read_bit("%M535") is False

    def test_rssi_safe_boundary_at_threshold(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(
            register_table=rt,
            auto_activate=True,
            rssi_trip_threshold_dbm=-75,
        )

        # Exactly at -75 dBm boundary -> NO trip
        safe = engine.evaluate_antenna_diversity(rssi_primary=-75, rssi_diversity=-75)
        assert safe is True
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL

    def test_default_82_dbm_threshold_trip_and_injection(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)
        assert engine.rssi_trip_threshold_dbm == -82

        # Inject severe degradation (-88 dBm primary, -90 dBm diversity)
        engine.inject_rssi_degradation(rssi_primary_dbm=-88, rssi_diversity_dbm=-90)
        assert engine.state == WiFi6SafetyState.SAFE_STOP_TRIPPED
        assert engine.diagnostic_code == 0xEE61
        assert rt.read_word("%R2291") == -88
        assert rt.read_word("%R2292") == -90
        assert rt.read_uword("%R2297") == 0xEE61
        assert rt.read_bit("%M535") is True

    def test_rssi_degradation_recovery_reset(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)
        engine.inject_rssi_degradation()
        assert engine.is_safe_stop_tripped is True

        engine.reset()
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.rssi_primary_dbm == NOMINAL_CIP_SAFETY_WIFI6_RSSI_PRIMARY_DBM
        assert engine.rssi_diversity_dbm == NOMINAL_CIP_SAFETY_WIFI6_RSSI_DIVERSITY_DBM
        assert rt.read_word("%R2290") == 3
        assert rt.read_word("%R2291") == -54
        assert rt.read_word("%R2292") == -58
        assert rt.read_uword("%R2297") == 0x0000
        assert rt.read_bit("%M534") is True
        assert rt.read_bit("%M535") is False


# ============================================================================
# 5. TestPacketErrorRateBurstTrip
# ============================================================================

class TestPacketErrorRateBurstTrip:
    """Validate Packet Error Rate (PER) burst trip (0xEE62) and EPI silence watchdog timeout trip (0xEE62)."""

    def test_per_burst_trip_exceeds_threshold(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)
        assert engine.per_trip_threshold_scaled == 500

        # Inject PER = 600 scaled (6.00% > 5.00% threshold)
        engine.inject_packet_error_burst(per_scaled=600)

        assert engine.state == WiFi6SafetyState.SAFE_STOP_TRIPPED
        assert engine.diagnostic_code == DiagnosticCode.PACKET_ERROR_BURST_TRIP
        assert engine.diagnostic_code == 0xEE62
        assert engine.diagnostic_code == -4510
        assert engine.is_safe_stop_tripped is True
        assert engine.is_healthy is False

        # Register reflection
        assert rt.read_word("%R2290") == 4
        assert rt.read_word("%R2293") == 600
        assert rt.read_uword("%R2297") == 0xEE62
        assert rt.read_bit("%M534") is False
        assert rt.read_bit("%M535") is True

    def test_per_safe_boundary_at_threshold_no_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)

        # Incoming packet with per_scaled exactly 500 (safe limit)
        pkt = create_valid_wifi6_packet(sequence_primary=1, per_scaled=500)
        processed = engine.process_packet(pkt)
        assert processed is True
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert rt.read_word("%R2293") == 500
        assert rt.read_bit("%M534") is True
        assert rt.read_bit("%M535") is False

    def test_process_packet_with_excessive_per_trips(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)

        pkt = create_valid_wifi6_packet(sequence_primary=2, per_scaled=550)
        processed = engine.process_packet(pkt)
        assert processed is False
        assert engine.state == WiFi6SafetyState.SAFE_STOP_TRIPPED
        assert engine.diagnostic_code == DiagnosticCode.PACKET_ERROR_BURST_TRIP
        assert rt.read_uword("%R2297") == 0xEE62
        assert rt.read_bit("%M535") is True

    def test_epi_silence_watchdog_timeout_trip_via_scan_steps(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(
            register_table=rt,
            auto_activate=True,
            epi_timeout_threshold_us=15000,
        )

        # Advance scan steps to accumulate silence (2 scans of 10 ms = 20,000 us > 15,000 us limit)
        engine.scan_step(0.010)
        assert engine.is_healthy is True
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL

        engine.scan_step(0.010)
        assert engine.state == WiFi6SafetyState.SAFE_STOP_TRIPPED
        assert engine.diagnostic_code == DiagnosticCode.PACKET_ERROR_BURST_TRIP
        assert engine.diagnostic_code == 0xEE62
        assert rt.read_word("%R2290") == 4
        assert rt.read_uword("%R2297") == 0xEE62
        assert rt.read_bit("%M535") is True

    def test_periodic_packet_reception_refreshes_watchdog_preventing_trip(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)

        # Advance 8 ms
        engine.scan_step(0.008)
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL

        # Process valid packet -> resets silence_timer_us to 0
        pkt = create_valid_wifi6_packet(sequence_primary=10)
        assert engine.process_packet(pkt) is True
        assert engine.silence_timer_us == 0.0

        # Advance another 8 ms (total 16 ms, but reset kept it alive)
        engine.scan_step(0.008)
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert rt.read_bit("%M534") is True

    def test_inject_watchdog_timeout_method(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)
        engine.inject_watchdog_timeout()
        assert engine.state == WiFi6SafetyState.SAFE_STOP_TRIPPED
        assert engine.diagnostic_code == 0xEE62
        assert rt.read_uword("%R2297") == 0xEE62
        assert rt.read_bit("%M535") is True

    def test_per_burst_recovery_reset(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)
        engine.inject_packet_error_burst(per_scaled=700)
        assert engine.is_safe_stop_tripped is True

        engine.reset()
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.per_scaled == NOMINAL_CIP_SAFETY_WIFI6_PER_SCALED
        assert rt.read_word("%R2293") == 12
        assert rt.read_uword("%R2297") == 0x0000
        assert rt.read_bit("%M534") is True
        assert rt.read_bit("%M535") is False


# ============================================================================
# 6. TestRoamingTimeoutFault
# ============================================================================

class TestRoamingTimeoutFault:
    """Validate IEEE 802.11r Fast BSS Transition roaming surveillance and roaming timeout fault (0xEE63)."""

    def test_roaming_initiation_and_event_count_increment(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)
        assert engine.roaming_event_count == 0
        assert rt.read_uword("%R2295") == 0

        engine.start_bss_roam(target_bssid="02:00:00:00:00:02")
        assert engine.is_roaming is True
        assert engine.state == WiFi6SafetyState.BSS_ASSOCIATING
        assert engine.roaming_event_count == 1
        assert engine.bssid == "02:00:00:00:00:02"

        # Register reflection
        assert rt.read_word("%R2290") == 1
        assert rt.read_uword("%R2295") == 1

    def test_roaming_timeout_watchdog_trip_via_scan_steps(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(
            register_table=rt,
            auto_activate=True,
            roaming_timeout_ms=50.0,
        )

        engine.start_bss_roam(target_bssid="02:00:00:00:00:03")

        # Advance 40 ms -> still within 50 ms limit
        for _ in range(4):
            engine.scan_step(0.010)
        assert engine.is_roaming is True
        assert engine.state == WiFi6SafetyState.BSS_ASSOCIATING
        assert engine.diagnostic_code == DiagnosticCode.OK

        # Advance 20 ms more (total 60 ms > 50 ms limit) -> TRIPS 0xEE63!
        for _ in range(2):
            engine.scan_step(0.010)

        assert engine.state == WiFi6SafetyState.SAFE_STOP_TRIPPED
        assert engine.diagnostic_code == DiagnosticCode.BSS_ROAM_TIMEOUT_FAULT
        assert engine.diagnostic_code == 0xEE63
        assert engine.diagnostic_code == -4509
        assert engine.is_roaming is False
        assert engine.is_safe_stop_tripped is True
        assert engine.is_healthy is False

        # Register reflection
        assert rt.read_word("%R2290") == 4
        assert rt.read_uword("%R2295") == 1
        assert rt.read_uword("%R2297") == 0xEE63
        assert rt.read_bit("%M534") is False
        assert rt.read_bit("%M535") is True

    def test_successful_roam_completion_without_fault(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)

        engine.start_bss_roam(target_bssid="02:00:00:00:00:04")
        assert engine.state == WiFi6SafetyState.BSS_ASSOCIATING

        # Progress to security handshake
        engine.progress_roam_security_handshake()
        assert engine.state == WiFi6SafetyState.SECURITY_HANDSHAKE
        assert rt.read_word("%R2290") == 2

        # Complete roam in timely manner (within 20 ms)
        engine.scan_step(0.020)
        engine.complete_bss_roam()

        assert engine.is_roaming is False
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert rt.read_word("%R2290") == 3
        assert rt.read_uword("%R2297") == 0x0000
        assert rt.read_bit("%M534") is True
        assert rt.read_bit("%M535") is False

    def test_inject_bss_roam_timeout_method(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)
        engine.inject_bss_roam_timeout()

        assert engine.state == WiFi6SafetyState.SAFE_STOP_TRIPPED
        assert engine.diagnostic_code == 0xEE63
        assert rt.read_uword("%R2297") == 0xEE63
        assert rt.read_bit("%M535") is True

    def test_roam_timeout_recovery_reset(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)
        engine.inject_bss_roam_timeout()
        assert engine.is_safe_stop_tripped is True

        engine.reset()
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_roaming is False
        assert engine.roaming_timer_ms == 0.0
        assert rt.read_word("%R2290") == 3
        assert rt.read_uword("%R2297") == 0x0000
        assert rt.read_bit("%M534") is True
        assert rt.read_bit("%M535") is False


# ============================================================================
# 7. TestDiversityAntennaFault
# ============================================================================

class TestDiversityAntennaFault:
    """Validate dual-antenna spatial diversity surveillance and diversity antenna fault (0xEE64)."""

    def test_diversity_antenna_severe_loss_or_disconnect(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)
        assert engine.diversity_fault_threshold_dbm == -85

        # Primary is healthy (-54 dBm), but Diversity antenna drops to -90 dBm (<= -85 dBm) -> TRIPS!
        safe = engine.evaluate_antenna_diversity(rssi_primary=-54, rssi_diversity=-90)
        assert safe is False
        assert engine.state == WiFi6SafetyState.SAFE_STOP_TRIPPED
        assert engine.diagnostic_code == DiagnosticCode.DIVERSITY_ANTENNA_FAULT
        assert engine.diagnostic_code == 0xEE64
        assert engine.diagnostic_code == -4508
        assert engine.is_safe_stop_tripped is True
        assert engine.is_healthy is False

        # Register reflection
        assert rt.read_word("%R2290") == 4
        assert rt.read_word("%R2291") == -54
        assert rt.read_word("%R2292") == -90
        assert rt.read_uword("%R2297") == 0xEE64
        assert rt.read_bit("%M534") is False
        assert rt.read_bit("%M535") is True

    def test_antenna_delta_exceeds_30_db_with_degraded_diversity(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)
        assert engine.max_antenna_delta_db == 30

        # Primary is -45 dBm, Diversity is -78 dBm (delta = 33 dB >= 30 dB and diversity < -75 dBm) -> TRIPS!
        safe = engine.evaluate_antenna_diversity(rssi_primary=-45, rssi_diversity=-78)
        assert safe is False
        assert engine.state == WiFi6SafetyState.SAFE_STOP_TRIPPED
        assert engine.diagnostic_code == DiagnosticCode.DIVERSITY_ANTENNA_FAULT
        assert rt.read_uword("%R2297") == 0xEE64
        assert rt.read_bit("%M535") is True

    def test_antenna_switching_hysteresis_logic(self) -> None:
        engine = CIPSafetyWiFi6Engine(auto_activate=True)
        assert engine.active_antenna == AntennaSelection.PRIMARY
        assert engine.antenna_switch_count == 0

        # Diversity is only 1 dB better (-53 vs -54) -> does NOT switch due to 2 dB hysteresis
        engine.evaluate_antenna_diversity(rssi_primary=-54, rssi_diversity=-53)
        assert engine.active_antenna == AntennaSelection.PRIMARY
        assert engine.antenna_switch_count == 0

        # Diversity improves to -51 dBm (> -54 + 2 dB) -> switches to DIVERSITY
        engine.evaluate_antenna_diversity(rssi_primary=-54, rssi_diversity=-51)
        assert engine.active_antenna == AntennaSelection.DIVERSITY
        assert engine.antenna_switch_count == 1

        # Primary improves to -50 dBm (only 1 dB better) -> does NOT switch back
        engine.evaluate_antenna_diversity(rssi_primary=-50, rssi_diversity=-51)
        assert engine.active_antenna == AntennaSelection.DIVERSITY
        assert engine.antenna_switch_count == 1

        # Primary improves to -48 dBm (>= -51 + 2 dB) -> switches back to PRIMARY
        engine.evaluate_antenna_diversity(rssi_primary=-48, rssi_diversity=-51)
        assert engine.active_antenna == AntennaSelection.PRIMARY
        assert engine.antenna_switch_count == 2

    def test_inject_diversity_fault_method(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)
        engine.inject_diversity_fault(rssi_diversity_dbm=-95)

        assert engine.state == WiFi6SafetyState.SAFE_STOP_TRIPPED
        assert engine.diagnostic_code == DiagnosticCode.DIVERSITY_ANTENNA_FAULT
        assert engine.diversity_antenna_fault is True
        assert rt.read_word("%R2292") == -95
        assert rt.read_uword("%R2297") == 0xEE64
        assert rt.read_bit("%M535") is True

    def test_diversity_fault_recovery_reset(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)
        engine.inject_diversity_fault()
        assert engine.is_safe_stop_tripped is True

        engine.reset()
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.diversity_antenna_fault is False
        assert engine.active_antenna == AntennaSelection.PRIMARY
        assert rt.read_word("%R2290") == 3
        assert rt.read_word("%R2292") == -58
        assert rt.read_uword("%R2297") == 0x0000
        assert rt.read_bit("%M534") is True
        assert rt.read_bit("%M535") is False


# ============================================================================
# 8. TestRegisterSynchronization
# ============================================================================

class TestRegisterSynchronization:
    """Validate bit-exact synchronization to Horner OCS %R2290..%R2297 and %M534..%M535."""

    def test_nominal_register_synchronization(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)

        assert rt.read_word("%R2290") == 3
        assert rt.read_word("%R2291") == -54
        assert rt.read_word("%R2292") == -58
        assert rt.read_word("%R2293") == 12
        assert rt.read_uword("%R2294") == 100
        assert rt.read_uword("%R2295") == 0
        assert rt.read_uword("%R2296") == 5000
        assert rt.read_uword("%R2297") == 0x0000

        assert rt.read_bit("%M534") is True
        assert rt.read_bit("%M535") is False

    def test_sequential_fault_trips_sync(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)

        fault_cases = [
            (DiagnosticCode.RSSI_DEGRADATION_TRIP, 0xEE61),
            (DiagnosticCode.PACKET_ERROR_BURST_TRIP, 0xEE62),
            (DiagnosticCode.BSS_ROAM_TIMEOUT_FAULT, 0xEE63),
            (DiagnosticCode.DIVERSITY_ANTENNA_FAULT, 0xEE64),
        ]

        for code, hex_code in fault_cases:
            engine.trip_fault(code)
            assert rt.read_word("%R2290") == 4
            assert rt.read_uword("%R2297") == hex_code
            assert rt.read_bit("%M534") is False
            assert rt.read_bit("%M535") is True

            engine.reset()
            assert rt.read_word("%R2290") == 3
            assert rt.read_uword("%R2297") == 0x0000
            assert rt.read_bit("%M534") is True
            assert rt.read_bit("%M535") is False

    def test_transmit_and_process_packet_sync(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)

        # Transmit packet
        pkt_tx = engine.transmit_packet(payload=b"\x01\x02\x03\x04")
        assert pkt_tx.sequence_primary == 1
        assert engine.tx_frame_count == 101
        assert rt.read_uword("%R2294") == 101

        # Process valid incoming packet
        pkt_rx = create_valid_wifi6_packet(
            sequence_primary=50,
            rssi_primary_dbm=-52,
            rssi_diversity_dbm=-56,
            per_scaled=15,
            epi_timer_us=4800,
        )
        assert engine.process_packet(pkt_rx) is True
        assert rt.read_word("%R2291") == -52
        assert rt.read_word("%R2292") == -56
        assert rt.read_word("%R2293") == 15
        assert rt.read_uword("%R2296") == 4800
        assert rt.read_uword("%R2297") == 0x0000

    def test_safe_write_wrappers(self) -> None:
        rt = RegisterTable()

        # Word wrapping test (> 32767 wraps to negative signed)
        safe_write_word(rt, "%R2290", 40000)
        assert rt.read_word("%R2290") == 40000 - 65536

        # UWord test
        safe_write_uword(rt, "%R2297", 0xEE61)
        assert rt.read_uword("%R2297") == 0xEE61

        # Bit test
        safe_write_bit(rt, "%M534", True)
        assert rt.read_bit("%M534") is True
        safe_write_bit(rt, "%M534", False)
        assert rt.read_bit("%M534") is False


# ============================================================================
# 9. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 ST POU verification with SecurityGuard and STParser."""

    def test_pure_st_pou_verification(self) -> None:
        assert verify_cip_safety_wifi6_pure_st() is True
        assert verify_cip_safety_wifi6_pure_st(CIP_SAFETY_WIFI6_PURE_ST_POU) is True
        assert verify_cip_safety_wifi6_pure_st(CIP_SAFETY_WIFI6_SYNC_POU) is True
        assert verify_cip_safety_wifi6_pure_st(CIP_SAFETY_WIFI6_POU) is True
        assert verify_cip_safety_wifi6_pure_st(PURE_ST_POU) is True
        assert verify_cip_safety_wifi6_pure_st(CipSafetyWiFi6Sync) is True
        assert verify_cip_safety_wifi6_pure_st(CipSafetyWiFi6SyncPOU) is True

    def test_security_guard_and_st_parser(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_WIFI6_PURE_ST_POU)
        res = STParser.validate_code(CIP_SAFETY_WIFI6_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(CIP_SAFETY_WIFI6_PURE_ST_POU)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R2290", "%R2291", "%R2292", "%R2293",
            "%R2294", "%R2295", "%R2296", "%R2297",
            "%M534", "%M535",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_ast_variable_memory_address_mappings(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_WIFI6_PURE_ST_POU)
        var_map = {
            v.name: getattr(v, "memory_address", getattr(v, "address_binding", None))
            for v in ast.variables
        }

        assert var_map["WiFi6SafetyLinkState"] == "%R2290"
        assert var_map["WiFi6RssiPrimaryDbm"] == "%R2291"
        assert var_map["WiFi6RssiDiversityDbm"] == "%R2292"
        assert var_map["WiFi6PerScaled"] == "%R2293"
        assert var_map["WiFi6TxFrameCount"] == "%R2294"
        assert var_map["WiFi6RoamingEventCount"] == "%R2295"
        assert var_map["WiFi6EpiTimerUs"] == "%R2296"
        assert var_map["WiFi6DiagnosticCode"] == "%R2297"
        assert var_map["WiFi6SafetyOperational"] == "%M534"
        assert var_map["WiFi6SafetyTripped"] == "%M535"

    def test_invalid_pou_fails_verification(self) -> None:
        invalid_pou = "PROGRAM CorruptPOU VAR X : INT; END_VAR X := 10; END_PROGRAM"
        assert verify_cip_safety_wifi6_pure_st(invalid_pou) is False


# ============================================================================
# 10. TestAntiLadderConstructRejection
# ============================================================================

class TestAntiLadderConstructRejection:
    """Verify security guard immediately rejects ladder constructs with LadderForbiddenError."""

    @pytest.mark.parametrize(
        "construct",
        [
            "---[ ]---",
            "---[/]---",
            "---( )---",
            "---(S)---",
            "---(R)---",
            "RUNG 10",
            "NETWORK 1",
            "XIC(Channel1);",
            "XIO(Channel2);",
            "OTE(Coil1);",
            "OTL(Latch1);",
            "OTU(Unlatch1);",
        ],
    )
    def test_ladder_constructs_rejected(self, construct: str) -> None:
        snippet = f"PROGRAM TestLadder\n VAR b : BOOL; END_VAR\n {construct}\n END_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# 11. TestILogicUnitComplianceAndSoak
# ============================================================================

class TestILogicUnitComplianceAndSoak:
    """Verify ILogicUnit compliance: properties, scan_step, step, execute, reset, and 100-cycle soak."""

    def test_ilogicunit_interface_properties(self) -> None:
        engine = CIPSafetyWiFi6Engine(auto_activate=True)
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "CIPSafetyWiFi6Engine"
        assert engine.priority == 10
        assert engine.is_enabled is True
        assert engine.is_healthy is True
        assert engine.link_healthy is True
        assert engine.is_safe_stop_tripped is False
        assert engine.safe_stop_tripped is False
        assert engine.wifi6_state == WiFi6SafetyState.SAFE_OPERATIONAL

    def test_scan_step_and_step(self) -> None:
        engine = CIPSafetyWiFi6Engine(auto_activate=True)
        assert engine.cycles_count == 0
        engine.scan_step(0.005)
        assert engine.cycles_count == 1

        engine.step(0.005)
        assert engine.cycles_count == 2

    def test_execute_scan_context(self) -> None:
        engine = CIPSafetyWiFi6Engine(auto_activate=True)
        ctx = ScanContext(cycle=1, dt_ms=5.0)
        engine.execute(ctx)
        assert engine.cycles_count == 1

    def test_100_cycle_soak_stability_and_heap_boundedness(self) -> None:
        rt = RegisterTable()
        engine = CIPSafetyWiFi6Engine(register_table=rt, auto_activate=True)

        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        for cycle_i in range(1, 101):
            pkt_in = engine.create_packet(seq=cycle_i)
            engine.process_packet(pkt_in)
            engine.scan_step(0.005)

        snapshot_after = tracemalloc.take_snapshot()
        stats = snapshot_after.compare_to(snapshot_before, "lineno")
        heap_growth_kb = sum(st.size_diff for st in stats if st.size_diff > 0) / 1024.0
        tracemalloc.stop()

        assert engine.cycles_count == 100
        assert heap_growth_kb < 100.0
        assert engine.state == WiFi6SafetyState.SAFE_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_healthy is True
        assert engine.is_safe_stop_tripped is False
        assert rt.read_word("%R2290") == 3
        assert rt.read_word("%R2291") == -54
        assert rt.read_uword("%R2297") == 0x0000
        assert rt.read_bit("%M534") is True
        assert rt.read_bit("%M535") is False

    def test_engine_class_aliases(self) -> None:
        assert CipSafetyWiFi6Engine is CIPSafetyWiFi6Engine
        assert CIPSafetyWifi6Engine is CIPSafetyWiFi6Engine
        assert CIPWiFi6SafetyEngine is CIPSafetyWiFi6Engine
        assert WiFi6SafetyEngine is CIPSafetyWiFi6Engine
        assert CIP_SAFETY_WIFI6_ENGINE is CIPSafetyWiFi6Engine


# ============================================================================
# 12. TestExceptionsAndVerificationRunner
# ============================================================================

class TestExceptionsAndVerificationRunner:
    """Verify custom exception inheritance, 10-stage verification runner, and strict 4-state contract."""

    def test_exception_inheritance_hierarchy(self) -> None:
        assert issubclass(WiFi6RssiDegradationError, CIPWiFi6SafetyError)
        assert issubclass(WiFi6PacketErrorBurstError, CIPWiFi6SafetyError)
        assert issubclass(WiFi6BssRoamTimeoutError, CIPWiFi6SafetyError)
        assert issubclass(WiFi6DiversityAntennaError, CIPWiFi6SafetyError)
        assert issubclass(CIPWiFi6SafetyError, Exception)

    def test_verification_runner_execution(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = tf.name

        try:
            result = run_cip_safety_wifi6_verification(output_path=temp_path)
            assert isinstance(result, dict)
            assert result["status"] == "success"
            assert result["error_code"] is None
            assert result["stages_passed"] == 10
            assert result["total_stages"] == 10
            assert result["work_package"] == "W268"

            # Verify saved JSON evidence
            with open(temp_path, "r", encoding="utf-8") as f:
                saved_evidence = json.load(f)
            assert saved_evidence["status"] == "success"
            assert saved_evidence["stages_passed"] == 10
        finally:
            Path(temp_path).unlink(missing_ok=True)
