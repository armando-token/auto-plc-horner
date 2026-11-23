"""Comprehensive Unit Test Suite for Wave W256 CIP Safety Over 5G URLLC Protocol Engine.

Work Package: W256 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Over 5G URLLC (3GPP Rel-16/17 Delay-Critical GBR) for Horner OCS.

Covers Comprehensive Deterministic Unit Tests across 12 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit values, string representations,
   bitwise operations, hashing, enums, register names, coil addresses, and class IDs.
2. TestCrcSAndPacketFraming: CRC-S1 (0x5935), CRC-S2 (0x755B), EPID CRC32 hashing, diversified sequence
   counters (~seq_1 & 0xFFFF), frame serialization, and single-bit mutation corruption detection.
3. TestStateTransitions: IDLE -> ATTACHING_NPN -> URLLC_SESSION_ESTABLISHED -> AUTHENTICATED_OPERATIONAL ->
   URLLC_TIMEOUT_SAFE_STOP state transitions, connect, disconnect, trip_fault, and recovery resets.
4. TestRsrpSignalDegradationSurveillance: 5G RSRP nominal tracking (-75 dBm), safe boundaries (-110 dBm),
   degradation trip (< -110 dBm -> 0xEE21 RSRP_DROP_TRIP), register reflection, and recovery reset.
5. TestSinrNoiseInterferenceSurveillance: 5G SINR nominal tracking (18 dB), safe boundaries (0 dB),
   noise interference trip (< 0 dB -> 0xEE22 SINR_NOISE_TRIP), register reflection, and recovery reset.
6. TestUrllcLatencyOverrunSurveillance: URLLC air latency nominal tracking (950 us), latency trip
   (> 10,000 us -> 0xEE23 LATENCY_OVERRUN_TRIP), packet loss trip (> 1,000 ppm -> 0xEE23),
   silence watchdog timer (10.0 ms timeout -> 0xEE23), packet arrival silence reset, and recovery reset.
7. TestEpidAuthenticationAndSecurity: EPID authentication verification, rogue 5G node rejection (0xEE24
   AUTH_FAIL_TRIP), diversified sequence corruption detection, and CRC fault trip.
8. TestRegisterSynchronization: %R2170..%R2177 and %M506..%M507 bit-exact synchronization, PrivilegeMode.SYSTEM,
   cumulative handover count (%R2176), transmit sequence, and safe write wrappers.
9. TestPureSTAndSecurity: STParser & SecurityGuard verification of CipSafety5GUrllcSync POU, bound registers validation.
10. TestAntiLadderConstructRejection: Rejection of ladder logic constructs (contacts, coils, rungs, networks, mnemonics)
    with LadderForbiddenError.
11. TestILogicUnitComplianceAndSoak: ILogicUnit interface compliance (scan_step, step, execute, reset),
    properties validation, 100-cycle continuous soak simulation, and heap boundedness (< 100 KB growth).
12. TestVerificationRunnerAndContract: Deterministic 10-stage runner execution, strict 4-state contract validation,
    and exception inheritance hierarchy.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import tracemalloc
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_5g_urllc import (
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_5G_URLLC_CLASS_ID,
    CIP_SAFETY_URLLC_CLASS_ID,
    NOMINAL_5G_RSRP_DBM,
    DEFAULT_RSRP_DBM,
    MIN_RSRP_DBM,
    MAX_RSRP_DBM,
    DEFAULT_RSRP_TRIP_THRESHOLD_DBM,
    NOMINAL_5G_SINR_DB,
    DEFAULT_SINR_DB,
    MIN_SINR_DB,
    MAX_SINR_DB,
    DEFAULT_SINR_TRIP_THRESHOLD_DB,
    NOMINAL_URLLC_LATENCY_US,
    NOMINAL_5G_LATENCY_US,
    DEFAULT_LATENCY_US,
    MIN_LATENCY_US,
    MAX_LATENCY_US,
    DEFAULT_LATENCY_TRIP_THRESHOLD_US,
    NOMINAL_URLLC_PACKET_LOSS_RATE_PPM,
    DEFAULT_PACKET_LOSS_RATE_PPM,
    MIN_PACKET_LOSS_RATE_PPM,
    MAX_PACKET_LOSS_RATE_PPM,
    DEFAULT_PACKET_LOSS_TRIP_THRESHOLD_PPM,
    NOMINAL_5G_QOS_FLOW_ID,
    DEFAULT_QOS_FLOW_ID,
    DEFAULT_5QI,
    DEFAULT_5QI_FLOW_ID,
    DEFAULT_FIVE_QI,
    NOMINAL_5G_HANDOVER_COUNT,
    DEFAULT_HANDOVER_COUNT,
    NOMINAL_5G_WATCHDOG_MS,
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
    REG_5G_SAFETY_LINK_STATE,
    REG_5G_RSRP_DBM,
    REG_5G_SINR_DB,
    REG_URLLC_LATENCY_US,
    REG_URLLC_PACKET_LOSS_RATE_PPM,
    REG_5G_QOS_FLOW_ID,
    REG_5G_HANDOVER_COUNT,
    REG_5G_SAFETY_DIAGNOSTIC_CODE,
    COIL_5G_SAFETY_LINK_HEALTHY,
    COIL_5G_SAFETY_STOP_TRIPPED,
    REG_URLLC_SAFETY_STATE,
    REG_5G_SAFETY_STATE,
    REG_5G_STATE,
    REG_SAFETY_LINK_STATE,
    REG_SAFETY_STATE,
    REG_URLLC_RSRP_DBM,
    REG_RSRP_DBM,
    REG_5G_RSRP,
    REG_URLLC_SINR_DB,
    REG_SINR_DB,
    REG_5G_SINR,
    REG_5G_LATENCY_US,
    REG_LATENCY_US,
    REG_PACKET_LOSS_RATE_PPM,
    REG_PACKET_LOSS_PPM,
    REG_5G_PACKET_LOSS_PPM,
    REG_URLLC_FIVE_QI_FLOW_ID,
    REG_QOS_FLOW_ID,
    REG_5G_QFI,
    REG_5QI,
    REG_5QI_FLOW_ID,
    REG_FIVE_QI_FLOW_ID,
    REG_URLLC_RADIO_BEAM_ID,
    REG_5G_RADIO_BEAM_ID,
    REG_RADIO_BEAM_ID,
    REG_BEAM_ID,
    REG_HANDOVER_COUNT,
    REG_5G_HANDOVERS,
    REG_SAFETY_TRANSMIT_SEQUENCE,
    REG_TRANSMIT_SEQUENCE,
    REG_SAFETY_SEQUENCE,
    REG_URLLC_DIAGNOSTIC_STATUS_CODE,
    REG_5G_DIAGNOSTIC_STATUS_CODE,
    REG_5G_DIAGNOSTIC_CODE,
    REG_SAFETY_DIAGNOSTIC_CODE,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_DIAGNOSTIC_CODE,
    COIL_URLLC_SAFETY_LINK_HEALTHY,
    COIL_SAFETY_LINK_HEALTHY,
    COIL_5G_LINK_HEALTHY,
    COIL_LINK_HEALTHY,
    COIL_URLLC_SAFETY_STOP_TRIPPED,
    COIL_SAFETY_STOP_TRIPPED,
    COIL_SAFE_STOP_TRIPPED,
    COIL_5G_STOP_TRIPPED,
    DiagnosticCode,
    DIAG_OK,
    DIAG_RSRP_DROP_TRIP,
    DIAG_SINR_NOISE_TRIP,
    DIAG_LATENCY_OVERRUN_TRIP,
    DIAG_AUTH_FAIL_TRIP,
    DiagnosticStatusCode,
    CIP5GDiagnosticCode,
    Cip5GDiagnosticCode,
    FiveGDiagnosticCode,
    URLLCDiagnosticCode,
    CipSafety5gUrllcDiagnosticCode,
    Safe5GState,
    Cip5GSafetyState,
    CIP5GSafetyState,
    Safe5GLinkState,
    FiveGSafetyState,
    URLLCSafetyState,
    CipSafety5gUrllcState,
    SafeURLLCState,
    URLLCState,
    CIP5GSafetyError,
    CIP5GURLLCSafetyError,
    CIP5GRsrpDropError,
    URLLCRsrpDropError,
    CIP5GSinrNoiseError,
    URLLCSinrInterferenceError,
    CIP5GLatencyOverrunError,
    URLLCLatencyOverrunError,
    CIP5GAuthenticationError,
    URLLCAuthenticationError,
    CIP5GWatchdogTimeoutError,
    URLLCWatchdogTimeoutError,
    CIP5GCrcFaultError,
    URLLCCrcFaultError,
    CIP_SAFETY_5G_URLLC_PURE_ST_POU,
    CIP_SAFETY_5G_URLLC_SYNC_POU,
    CIP_SAFETY_5G_URLLC_POU,
    CIP_SAFETY_5G_POU,
    PURE_ST_POU,
    CipSafety5GUrllcSync,
    CipSafety5GUrllcSyncPOU,
    CipSafety5gUrllcSync,
    verify_cip_safety_5g_urllc_pure_st,
    compute_crc_s1,
    compute_crc_s2,
    calc_crc_s1,
    calc_crc_s2,
    compute_epid_hash,
    compute_flow_id_hash,
    verify_dual_crc_s,
    safe_write_word,
    safe_write_uword,
    safe_write_bit,
    CIP5GSafetyURLLCPacket,
    CIP5GURLLCSafetyPacket,
    CIP5GSafetyPacket,
    CipSafety5GUrllcPacket,
    create_valid_5g_safety_packet,
    create_valid_5g_urllc_packet,
    CIP5GSafetyURLLCEngine,
    CIP5GURLLCSafetyEngine,
    CipSafety5GUrllcEngine,
    CIP5GSafetyEngine,
    CIPSafety5GUrllcEngine,
    CIP_SAFETY_5G_URLLC_ENGINE,
    run_cip_safety_5g_urllc_verification,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety 5G URLLC constants, enums, register names, and diagnostic codes."""

    def test_class_ids(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_SAFETY_5G_URLLC_CLASS_ID == 0x2F
        assert CIP_SAFETY_URLLC_CLASS_ID == 0x2F

    def test_crc_polynomial_constants(self) -> None:
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC_S_INIT == 0xFFFF
        assert CRC16_CCITT_POLY == 0x1021
        assert CRC16_CCITT_INIT == 0xFFFF

    def test_radio_and_qos_metric_limits(self) -> None:
        assert NOMINAL_5G_RSRP_DBM == -75
        assert DEFAULT_RSRP_DBM == -75
        assert MIN_RSRP_DBM == -140
        assert MAX_RSRP_DBM == -40
        assert DEFAULT_RSRP_TRIP_THRESHOLD_DBM == -110

        assert NOMINAL_5G_SINR_DB == 18
        assert DEFAULT_SINR_DB == 18
        assert MIN_SINR_DB == -10
        assert MAX_SINR_DB == 30
        assert DEFAULT_SINR_TRIP_THRESHOLD_DB == 0

        assert NOMINAL_URLLC_LATENCY_US == 950
        assert NOMINAL_5G_LATENCY_US == 950
        assert DEFAULT_LATENCY_US == 950
        assert MIN_LATENCY_US == 100
        assert MAX_LATENCY_US == 20000
        assert DEFAULT_LATENCY_TRIP_THRESHOLD_US == 10000

        assert NOMINAL_URLLC_PACKET_LOSS_RATE_PPM == 1
        assert DEFAULT_PACKET_LOSS_RATE_PPM == 1
        assert MIN_PACKET_LOSS_RATE_PPM == 0
        assert MAX_PACKET_LOSS_RATE_PPM == 10000
        assert DEFAULT_PACKET_LOSS_TRIP_THRESHOLD_PPM == 1000

        assert NOMINAL_5G_QOS_FLOW_ID == 82
        assert DEFAULT_QOS_FLOW_ID == 82
        assert DEFAULT_5QI == 82
        assert DEFAULT_5QI_FLOW_ID == 82
        assert DEFAULT_FIVE_QI == 82

        assert NOMINAL_5G_HANDOVER_COUNT == 0
        assert DEFAULT_HANDOVER_COUNT == 0

        assert NOMINAL_5G_WATCHDOG_MS == 10.0
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 10.0
        assert DEFAULT_SAFETY_EPID == "HORNER-OCS-5G-URLLC-SIL3"
        assert DEFAULT_EPID == "HORNER-OCS-5G-URLLC-SIL3"

    def test_register_mappings_and_aliases(self) -> None:
        assert REG_5G_SAFETY_LINK_STATE == "%R2170"
        assert REG_URLLC_SAFETY_STATE == "%R2170"
        assert REG_5G_SAFETY_STATE == "%R2170"
        assert REG_5G_STATE == "%R2170"
        assert REG_SAFETY_LINK_STATE == "%R2170"
        assert REG_SAFETY_STATE == "%R2170"

        assert REG_5G_RSRP_DBM == "%R2171"
        assert REG_URLLC_RSRP_DBM == "%R2171"
        assert REG_RSRP_DBM == "%R2171"
        assert REG_5G_RSRP == "%R2171"

        assert REG_5G_SINR_DB == "%R2172"
        assert REG_URLLC_SINR_DB == "%R2172"
        assert REG_SINR_DB == "%R2172"
        assert REG_5G_SINR == "%R2172"

        assert REG_URLLC_LATENCY_US == "%R2173"
        assert REG_5G_LATENCY_US == "%R2173"
        assert REG_LATENCY_US == "%R2173"

        assert REG_URLLC_PACKET_LOSS_RATE_PPM == "%R2174"
        assert REG_PACKET_LOSS_RATE_PPM == "%R2174"
        assert REG_PACKET_LOSS_PPM == "%R2174"
        assert REG_5G_PACKET_LOSS_PPM == "%R2174"

        assert REG_5G_QOS_FLOW_ID == "%R2175"
        assert REG_QOS_FLOW_ID == "%R2175"
        assert REG_5G_QFI == "%R2175"
        assert REG_5QI == "%R2175"
        assert REG_URLLC_FIVE_QI_FLOW_ID == "%R2175"
        assert REG_5QI_FLOW_ID == "%R2175"
        assert REG_FIVE_QI_FLOW_ID == "%R2175"

        assert REG_5G_HANDOVER_COUNT == "%R2176"
        assert REG_HANDOVER_COUNT == "%R2176"
        assert REG_5G_HANDOVERS == "%R2176"
        assert REG_SAFETY_TRANSMIT_SEQUENCE == "%R2176"
        assert REG_TRANSMIT_SEQUENCE == "%R2176"
        assert REG_SAFETY_SEQUENCE == "%R2176"

        assert REG_5G_SAFETY_DIAGNOSTIC_CODE == "%R2177"
        assert REG_URLLC_DIAGNOSTIC_STATUS_CODE == "%R2177"
        assert REG_5G_DIAGNOSTIC_STATUS_CODE == "%R2177"
        assert REG_5G_DIAGNOSTIC_CODE == "%R2177"
        assert REG_SAFETY_DIAGNOSTIC_CODE == "%R2177"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2177"
        assert REG_DIAGNOSTIC_CODE == "%R2177"

        assert COIL_5G_SAFETY_LINK_HEALTHY == "%M506"
        assert COIL_URLLC_SAFETY_LINK_HEALTHY == "%M506"
        assert COIL_SAFETY_LINK_HEALTHY == "%M506"
        assert COIL_5G_LINK_HEALTHY == "%M506"
        assert COIL_LINK_HEALTHY == "%M506"

        assert COIL_5G_SAFETY_STOP_TRIPPED == "%M507"
        assert COIL_URLLC_SAFETY_STOP_TRIPPED == "%M507"
        assert COIL_SAFETY_STOP_TRIPPED == "%M507"
        assert COIL_SAFE_STOP_TRIPPED == "%M507"
        assert COIL_5G_STOP_TRIPPED == "%M507"

    def test_diagnostic_codes_signed_unsigned_equality(self) -> None:
        # 0x0000: OK
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.OK == 0
        assert (DiagnosticCode.OK & 0xFFFF) == 0x0000
        assert int(DiagnosticCode.OK) == 0

        # 0xEE21: RSRP_DROP_TRIP (signed: 0xEE21 - 0x10000 = -4575)
        assert DiagnosticCode.RSRP_DROP_TRIP == 0xEE21
        assert (DiagnosticCode.RSRP_DROP_TRIP & 0xFFFF) == 0xEE21
        assert DiagnosticCode.RSRP_DROP_TRIP == (0xEE21 - 0x10000)
        assert DiagnosticCode.RSRP_DROP_TRIP == -4575

        # 0xEE22: SINR_NOISE_TRIP (signed: 0xEE22 - 0x10000 = -4574)
        assert DiagnosticCode.SINR_NOISE_TRIP == 0xEE22
        assert (DiagnosticCode.SINR_NOISE_TRIP & 0xFFFF) == 0xEE22
        assert DiagnosticCode.SINR_NOISE_TRIP == (0xEE22 - 0x10000)
        assert DiagnosticCode.SINR_NOISE_TRIP == -4574

        # 0xEE23: LATENCY_OVERRUN_TRIP (signed: 0xEE23 - 0x10000 = -4573)
        assert DiagnosticCode.LATENCY_OVERRUN_TRIP == 0xEE23
        assert (DiagnosticCode.LATENCY_OVERRUN_TRIP & 0xFFFF) == 0xEE23
        assert DiagnosticCode.LATENCY_OVERRUN_TRIP == (0xEE23 - 0x10000)
        assert DiagnosticCode.LATENCY_OVERRUN_TRIP == -4573

        # 0xEE24: AUTH_FAIL_TRIP (signed: 0xEE24 - 0x10000 = -4572)
        assert DiagnosticCode.AUTH_FAIL_TRIP == 0xEE24
        assert (DiagnosticCode.AUTH_FAIL_TRIP & 0xFFFF) == 0xEE24
        assert DiagnosticCode.AUTH_FAIL_TRIP == (0xEE24 - 0x10000)
        assert DiagnosticCode.AUTH_FAIL_TRIP == -4572

    def test_diagnostic_code_string_and_repr(self) -> None:
        assert str(DiagnosticCode.OK) == "0x0000 (OK)"
        assert str(DiagnosticCode.RSRP_DROP_TRIP) == "0xEE21 (RSRP_DROP_TRIP)"
        assert str(DiagnosticCode.SINR_NOISE_TRIP) == "0xEE22 (SINR_NOISE_TRIP)"
        assert str(DiagnosticCode.LATENCY_OVERRUN_TRIP) == "0xEE23 (LATENCY_OVERRUN_TRIP)"
        assert str(DiagnosticCode.AUTH_FAIL_TRIP) == "0xEE24 (AUTH_FAIL_TRIP)"

        assert repr(DiagnosticCode.OK) == "DiagnosticCode.OK(0x0000)"
        assert repr(DiagnosticCode.RSRP_DROP_TRIP) == "DiagnosticCode.RSRP_DROP_TRIP(0xEE21)"
        assert repr(DiagnosticCode.SINR_NOISE_TRIP) == "DiagnosticCode.SINR_NOISE_TRIP(0xEE22)"
        assert repr(DiagnosticCode.LATENCY_OVERRUN_TRIP) == "DiagnosticCode.LATENCY_OVERRUN_TRIP(0xEE23)"
        assert repr(DiagnosticCode.AUTH_FAIL_TRIP) == "DiagnosticCode.AUTH_FAIL_TRIP(0xEE24)"

    def test_diagnostic_code_bitwise_and_hashing(self) -> None:
        assert (DiagnosticCode.RSRP_DROP_TRIP & 0xFFFF) == 0xEE21
        assert (0xFFFF & DiagnosticCode.RSRP_DROP_TRIP) == 0xEE21
        assert (DiagnosticCode.SINR_NOISE_TRIP & 0xFFFF) == 0xEE22
        assert (DiagnosticCode.LATENCY_OVERRUN_TRIP & 0xFFFF) == 0xEE23
        assert (DiagnosticCode.AUTH_FAIL_TRIP & 0xFFFF) == 0xEE24

        diag_set = {
            DiagnosticCode.OK,
            DiagnosticCode.RSRP_DROP_TRIP,
            DiagnosticCode.SINR_NOISE_TRIP,
            DiagnosticCode.LATENCY_OVERRUN_TRIP,
            DiagnosticCode.AUTH_FAIL_TRIP,
        }
        assert len(diag_set) == 5
        assert DiagnosticCode.OK in diag_set
        assert DiagnosticCode.RSRP_DROP_TRIP in diag_set
        assert DiagnosticCode.SINR_NOISE_TRIP in diag_set
        assert DiagnosticCode.LATENCY_OVERRUN_TRIP in diag_set
        assert DiagnosticCode.AUTH_FAIL_TRIP in diag_set

    def test_diagnostic_code_aliases(self) -> None:
        assert DiagnosticCode.SAFETY_OK == DiagnosticCode.OK
        assert DiagnosticCode.LINK_OK == DiagnosticCode.OK
        assert DiagnosticCode.URLLC_SAFETY_OK == DiagnosticCode.OK
        assert DiagnosticCode.RSRP_DROP == DiagnosticCode.RSRP_DROP_TRIP
        assert DiagnosticCode.RSRP_LOW_TRIP == DiagnosticCode.RSRP_DROP_TRIP
        assert DiagnosticCode.ERR_RSRP_DROP == DiagnosticCode.RSRP_DROP_TRIP
        assert DiagnosticCode.SINR_NOISE == DiagnosticCode.SINR_NOISE_TRIP
        assert DiagnosticCode.SINR_LOW_TRIP == DiagnosticCode.SINR_NOISE_TRIP
        assert DiagnosticCode.ERR_SINR_NOISE == DiagnosticCode.SINR_NOISE_TRIP
        assert DiagnosticCode.SINR_INTERFERENCE_TRIP == DiagnosticCode.SINR_NOISE_TRIP
        assert DiagnosticCode.SINR_INTERFERENCE == DiagnosticCode.SINR_NOISE_TRIP
        assert DiagnosticCode.ERR_SINR_INTERFERENCE == DiagnosticCode.SINR_NOISE_TRIP
        assert DiagnosticCode.LATENCY_OVERRUN == DiagnosticCode.LATENCY_OVERRUN_TRIP
        assert DiagnosticCode.LATENCY_EXCEEDED_TRIP == DiagnosticCode.LATENCY_OVERRUN_TRIP
        assert DiagnosticCode.URLLC_TIMEOUT_TRIP == DiagnosticCode.LATENCY_OVERRUN_TRIP
        assert DiagnosticCode.WATCHDOG_TIMEOUT == DiagnosticCode.LATENCY_OVERRUN_TRIP
        assert DiagnosticCode.WATCHDOG_COMM_TIMEOUT == DiagnosticCode.LATENCY_OVERRUN_TRIP
        assert DiagnosticCode.ERR_LATENCY_OVERRUN == DiagnosticCode.LATENCY_OVERRUN_TRIP
        assert DiagnosticCode.AUTH_FAIL == DiagnosticCode.AUTH_FAIL_TRIP
        assert DiagnosticCode.AUTHENTICATION_FAILURE == DiagnosticCode.AUTH_FAIL_TRIP
        assert DiagnosticCode.EPID_MISMATCH_TRIP == DiagnosticCode.AUTH_FAIL_TRIP
        assert DiagnosticCode.FLOW_ID_MISMATCH_TRIP == DiagnosticCode.AUTH_FAIL_TRIP
        assert DiagnosticCode.CRC_FAULT == DiagnosticCode.AUTH_FAIL_TRIP
        assert DiagnosticCode.CRC_S_CHECKSUM_FAULT == DiagnosticCode.AUTH_FAIL_TRIP
        assert DiagnosticCode.ERR_AUTH_FAIL == DiagnosticCode.AUTH_FAIL_TRIP

        assert DIAG_OK == DiagnosticCode.OK
        assert DIAG_RSRP_DROP_TRIP == DiagnosticCode.RSRP_DROP_TRIP
        assert DIAG_SINR_NOISE_TRIP == DiagnosticCode.SINR_NOISE_TRIP
        assert DIAG_LATENCY_OVERRUN_TRIP == DiagnosticCode.LATENCY_OVERRUN_TRIP
        assert DIAG_AUTH_FAIL_TRIP == DiagnosticCode.AUTH_FAIL_TRIP

        assert DiagnosticStatusCode == DiagnosticCode
        assert CIP5GDiagnosticCode == DiagnosticCode
        assert Cip5GDiagnosticCode == DiagnosticCode
        assert FiveGDiagnosticCode == DiagnosticCode
        assert URLLCDiagnosticCode == DiagnosticCode
        assert CipSafety5gUrllcDiagnosticCode == DiagnosticCode

    def test_safe_5g_state_enum_and_aliases(self) -> None:
        assert Safe5GState.IDLE == 0
        assert Safe5GState.ATTACHING_NPN == 1
        assert Safe5GState.URLLC_SESSION_ESTABLISHED == 2
        assert Safe5GState.AUTHENTICATED_OPERATIONAL == 3
        assert Safe5GState.URLLC_TIMEOUT_SAFE_STOP == 4

        # Aliases
        assert Safe5GState.Idle == 0
        assert Safe5GState.AttachingNpn == 1
        assert Safe5GState.UrllcSessionEstablished == 2
        assert Safe5GState.AuthenticatedOperational == 3
        assert Safe5GState.UrllcTimeoutSafeStop == 4
        assert Safe5GState.OPERATIONAL == 3
        assert Safe5GState.SAFE_STOP == 4
        assert Safe5GState.TRIPPED == 4
        assert Safe5GState.DISCONNECTED == 0
        assert Safe5GState.SEARCHING == 1
        assert Safe5GState.Attaching == 1
        assert Safe5GState.PDU_SESSION_ESTABLISHED == 2
        assert Safe5GState.SafeStop == 4

        assert Cip5GSafetyState == Safe5GState
        assert CIP5GSafetyState == Safe5GState
        assert Safe5GLinkState == Safe5GState
        assert FiveGSafetyState == Safe5GState
        assert URLLCSafetyState == Safe5GState
        assert CipSafety5gUrllcState == Safe5GState
        assert SafeURLLCState == Safe5GState
        assert URLLCState == Safe5GState


# ============================================================================
# 2. TestCrcSAndPacketFraming
# ============================================================================

class TestCrcSAndPacketFraming:
    """Validate dual CRC-S1 / CRC-S2 calculation, sequence diversification, and corruption detection."""

    def test_crc_calculation_distinct(self) -> None:
        payload = b"HornerOCS-5G-URLLC-SafePayload-2026"
        c1 = compute_crc_s1(payload)
        c2 = compute_crc_s2(payload)

        assert 0 <= c1 <= 0xFFFF
        assert 0 <= c2 <= 0xFFFF
        assert c1 != 0 and c2 != 0
        assert c1 != c2  # Distinct polynomials 0x5935 vs 0x755B
        assert calc_crc_s1(payload) == c1
        assert calc_crc_s2(payload) == c2

    def test_crc_multi_argument_joining(self) -> None:
        p1 = b"Part1-"
        p2 = b"Part2"
        combined = b"Part1-Part2"
        assert compute_crc_s1(p1, p2) == compute_crc_s1(combined)
        assert compute_crc_s2(p1, p2) == compute_crc_s2(combined)

    def test_crc_invalid_argument_raises(self) -> None:
        with pytest.raises(ValueError):
            compute_crc_s1(12345)  # type: ignore

    def test_epid_and_flow_id_hashing(self) -> None:
        h1 = compute_epid_hash("HORNER-OCS-5G-URLLC-SIL3")
        h2 = compute_epid_hash(b"HORNER-OCS-5G-URLLC-SIL3")
        assert h1 == h2
        assert isinstance(h1, int)
        assert 0 <= h1 <= 0xFFFFFFFF
        assert h1 != compute_epid_hash("DIFFERENT-EPID")

        hf = compute_flow_id_hash(82)
        assert isinstance(hf, int)
        assert 0 <= hf <= 0xFFFFFFFF

    def test_verify_dual_crc_s_helper(self) -> None:
        d1 = b"Data1-5G"
        d2 = b"Data2-5G"
        c1 = compute_crc_s1(d1)
        c2 = compute_crc_s2(d2)

        assert verify_dual_crc_s(d1, d2, c1, c2) is True
        assert verify_dual_crc_s(d1, d2, c1 ^ 1, c2) is False
        assert verify_dual_crc_s(d1, d2, c1, c2 ^ 1) is False

    def test_packet_creation_and_crc_verification(self) -> None:
        pkt = create_valid_5g_safety_packet(sequence_primary=42)
        assert pkt.sequence_primary == 42
        assert pkt.sequence_diversified == (~42) & 0xFFFF
        assert pkt.verify_sequence() is True
        assert pkt.verify_crcs() is True

        pkt2 = create_valid_5g_urllc_packet(sequence_primary=42)
        assert pkt2.verify_sequence() is True
        assert pkt2.verify_crcs() is True

    def test_packet_payload_mutation_detected(self) -> None:
        pkt = create_valid_5g_safety_packet(sequence_primary=100)
        assert pkt.verify_crcs() is True

        # Mutate payload
        pkt.mutate_bit(byte_offset=0, bit_pos=2)
        assert pkt.verify_crcs() is False

    def test_packet_sequence_diversification_check(self) -> None:
        pkt = create_valid_5g_safety_packet(sequence_primary=500)
        assert pkt.verify_sequence() is True

        # Corrupt diversified sequence
        pkt.sequence_diversified = pkt.sequence_primary
        assert pkt.verify_sequence() is False


# ============================================================================
# 3. TestStateTransitions
# ============================================================================

class TestStateTransitions:
    """Validate 5G URLLC state machine progression: IDLE -> ATTACHING -> ESTABLISHED -> OPERATIONAL -> SAFE_STOP."""

    def test_state_transitions_step_by_step(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=False)

        # Initial state is IDLE
        assert engine.state == Safe5GState.IDLE
        assert engine.safety_state == Safe5GState.IDLE
        assert engine.link_state == Safe5GState.IDLE
        assert engine.is_healthy is False
        assert engine.is_safe_stop_tripped is True
        assert rt.read_word("%R2170") == 0

        # Step 1: IDLE -> ATTACHING_NPN
        assert engine.attach_npn() is True
        assert engine.state == Safe5GState.ATTACHING_NPN
        assert rt.read_word("%R2170") == 1
        assert engine.is_healthy is False

        # Step 2: ATTACHING_NPN -> URLLC_SESSION_ESTABLISHED
        assert engine.establish_urllc_session() is True
        assert engine.state == Safe5GState.URLLC_SESSION_ESTABLISHED
        assert rt.read_word("%R2170") == 2
        assert engine.is_healthy is False

        # Step 3: URLLC_SESSION_ESTABLISHED -> AUTHENTICATED_OPERATIONAL
        assert engine.authenticate() is True
        assert engine.state == Safe5GState.AUTHENTICATED_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_healthy is True
        assert engine.is_safe_stop_tripped is False
        assert rt.read_word("%R2170") == 3
        assert rt.read_bit("%M506") is True
        assert rt.read_bit("%M507") is False

        # Step 4: Trip into URLLC_TIMEOUT_SAFE_STOP
        engine.trip_fault(DiagnosticCode.RSRP_DROP_TRIP, "RSRP low")
        assert engine.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP
        assert engine.diagnostic_code == DiagnosticCode.RSRP_DROP_TRIP
        assert engine.is_healthy is False
        assert engine.is_safe_stop_tripped is True
        assert rt.read_word("%R2170") == 4
        assert rt.read_uword("%R2177") == 0xEE21
        assert rt.read_bit("%M506") is False
        assert rt.read_bit("%M507") is True

    def test_connect_convenience_helper(self) -> None:
        engine = CIP5GSafetyURLLCEngine(auto_activate=False)
        assert engine.state == Safe5GState.IDLE
        assert engine.connect() is True
        assert engine.state == Safe5GState.AUTHENTICATED_OPERATIONAL
        assert engine.is_healthy is True

    def test_disconnect_returns_to_idle(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)
        assert engine.state == Safe5GState.AUTHENTICATED_OPERATIONAL

        engine.disconnect()
        assert engine.state == Safe5GState.IDLE
        assert rt.read_word("%R2170") == 0

    def test_reset_variants_restore_nominal(self) -> None:
        engine = CIP5GSafetyURLLCEngine(auto_activate=True)
        engine.trip_fault(DiagnosticCode.SINR_NOISE_TRIP)
        assert engine.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP

        engine.reset()
        assert engine.state == Safe5GState.AUTHENTICATED_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.is_healthy is True

        engine.trip_fault(DiagnosticCode.LATENCY_OVERRUN_TRIP)
        engine.operator_reset()
        assert engine.state == Safe5GState.AUTHENTICATED_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK

        engine.trip_fault(DiagnosticCode.AUTH_FAIL_TRIP)
        engine.fault_reset()
        assert engine.state == Safe5GState.AUTHENTICATED_OPERATIONAL
        assert engine.diagnostic_code == DiagnosticCode.OK


# ============================================================================
# 4. TestRsrpSignalDegradationSurveillance
# ============================================================================

class TestRsrpSignalDegradationSurveillance:
    """Validate 5G RSRP signal degradation surveillance and 0xEE21 trip handling."""

    def test_rsrp_nominal_processing(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)
        pkt = engine.create_packet(seq=1, rsrp_dbm=-75)

        assert engine.process_packet(pkt) is True
        assert engine.rsrp_dbm == -75
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert rt.read_word("%R2171") == -75
        assert rt.read_word("%R2170") == 3
        assert rt.read_bit("%M506") is True
        assert rt.read_bit("%M507") is False

    def test_rsrp_boundary_threshold(self) -> None:
        engine = CIP5GSafetyURLLCEngine(auto_activate=True)
        # Exactly at threshold -110 dBm is valid
        pkt = engine.create_packet(seq=2, rsrp_dbm=-110)
        assert engine.process_packet(pkt) is True
        assert engine.is_healthy is True

    def test_rsrp_degradation_trip_below_threshold(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)
        # Trip when RSRP < -110 dBm (e.g. -115 dBm)
        pkt = engine.create_packet(seq=3, rsrp_dbm=-115)

        assert engine.process_packet(pkt) is False
        assert engine.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP
        assert engine.diagnostic_code == DiagnosticCode.RSRP_DROP_TRIP
        assert engine.diagnostic_code == 0xEE21
        assert rt.read_word("%R2171") == -115
        assert rt.read_word("%R2170") == 4
        assert rt.read_uword("%R2177") == 0xEE21
        assert rt.read_bit("%M506") is False
        assert rt.read_bit("%M507") is True

    def test_rsrp_fault_injection_helper(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)
        engine.inject_rsrp_drop(-125)

        assert engine.rsrp_dbm == -125
        assert engine.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP
        assert engine.diagnostic_code == DiagnosticCode.RSRP_DROP_TRIP
        assert rt.read_word("%R2171") == -125
        assert rt.read_uword("%R2177") == 0xEE21
        assert rt.read_bit("%M506") is False
        assert rt.read_bit("%M507") is True

        # Recovery
        engine.reset()
        assert engine.rsrp_dbm == NOMINAL_5G_RSRP_DBM
        assert engine.is_healthy is True
        assert rt.read_word("%R2171") == NOMINAL_5G_RSRP_DBM
        assert rt.read_uword("%R2177") == 0x0000


# ============================================================================
# 5. TestSinrNoiseInterferenceSurveillance
# ============================================================================

class TestSinrNoiseInterferenceSurveillance:
    """Validate 5G SINR noise interference surveillance and 0xEE22 trip handling."""

    def test_sinr_nominal_processing(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)
        pkt = engine.create_packet(seq=1, sinr_db=18)

        assert engine.process_packet(pkt) is True
        assert engine.sinr_db == 18
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert rt.read_word("%R2172") == 18
        assert rt.read_bit("%M506") is True
        assert rt.read_bit("%M507") is False

    def test_sinr_boundary_threshold(self) -> None:
        engine = CIP5GSafetyURLLCEngine(auto_activate=True)
        # Exactly at threshold 0 dB is valid
        pkt = engine.create_packet(seq=2, sinr_db=0)
        assert engine.process_packet(pkt) is True
        assert engine.is_healthy is True

    def test_sinr_noise_trip_below_threshold(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)
        # Trip when SINR < 0 dB (e.g. -5 dB)
        pkt = engine.create_packet(seq=3, sinr_db=-5)

        assert engine.process_packet(pkt) is False
        assert engine.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP
        assert engine.diagnostic_code == DiagnosticCode.SINR_NOISE_TRIP
        assert engine.diagnostic_code == 0xEE22
        assert rt.read_word("%R2172") == -5
        assert rt.read_word("%R2170") == 4
        assert rt.read_uword("%R2177") == 0xEE22
        assert rt.read_bit("%M506") is False
        assert rt.read_bit("%M507") is True

    def test_sinr_fault_injection_helper(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)
        engine.inject_sinr_noise(-5)

        assert engine.sinr_db == -5
        assert engine.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP
        assert engine.diagnostic_code == DiagnosticCode.SINR_NOISE_TRIP
        assert rt.read_word("%R2172") == -5
        assert rt.read_uword("%R2177") == 0xEE22
        assert rt.read_bit("%M506") is False
        assert rt.read_bit("%M507") is True

        # Recovery
        engine.reset()
        assert engine.sinr_db == NOMINAL_5G_SINR_DB
        assert engine.is_healthy is True
        assert rt.read_word("%R2172") == NOMINAL_5G_SINR_DB
        assert rt.read_uword("%R2177") == 0x0000


# ============================================================================
# 6. TestUrllcLatencyOverrunSurveillance
# ============================================================================

class TestUrllcLatencyOverrunSurveillance:
    """Validate URLLC latency overrun, packet loss, and silence watchdog trips (0xEE23)."""

    def test_latency_nominal_processing(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)
        pkt = engine.create_packet(seq=1, latency_us=950)

        assert engine.process_packet(pkt) is True
        assert engine.latency_us == 950
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert rt.read_word("%R2173") == 950
        assert rt.read_bit("%M506") is True
        assert rt.read_bit("%M507") is False

    def test_latency_boundary_threshold(self) -> None:
        engine = CIP5GSafetyURLLCEngine(auto_activate=True)
        # Exactly 10,000 us (10 ms) is valid
        pkt = engine.create_packet(seq=2, latency_us=10000)
        assert engine.process_packet(pkt) is True
        assert engine.is_healthy is True

    def test_latency_overrun_trip_above_threshold(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)
        # Trip when latency > 10,000 us (e.g. 15,000 us)
        pkt = engine.create_packet(seq=3, latency_us=15000)

        assert engine.process_packet(pkt) is False
        assert engine.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP
        assert engine.diagnostic_code == DiagnosticCode.LATENCY_OVERRUN_TRIP
        assert engine.diagnostic_code == 0xEE23
        assert rt.read_word("%R2173") == 15000
        assert rt.read_word("%R2170") == 4
        assert rt.read_uword("%R2177") == 0xEE23
        assert rt.read_bit("%M506") is False
        assert rt.read_bit("%M507") is True

    def test_packet_loss_excursion_trip(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)
        # Trip when packet loss > 1000 ppm (e.g. 1500 ppm)
        pkt = engine.create_packet(seq=4, packet_loss_ppm=1500)

        assert engine.process_packet(pkt) is False
        assert engine.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP
        assert engine.diagnostic_code == DiagnosticCode.LATENCY_OVERRUN_TRIP
        assert rt.read_uword("%R2174") == 1500
        assert rt.read_uword("%R2177") == 0xEE23

    def test_silence_watchdog_timeout_trip(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True, watchdog_timeout_ms=10.0)

        # 0.005s (5ms) elapsed: no trip yet
        engine.scan_step(0.005)
        assert engine.is_healthy is True
        assert engine.diagnostic_code == DiagnosticCode.OK

        # Another 0.006s (6ms) elapsed -> 11ms total > 10ms threshold: trips 0xEE23
        engine.scan_step(0.006)
        assert engine.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP
        assert engine.diagnostic_code == DiagnosticCode.LATENCY_OVERRUN_TRIP
        assert rt.read_uword("%R2177") == 0xEE23
        assert rt.read_bit("%M506") is False
        assert rt.read_bit("%M507") is True

    def test_packet_arrival_resets_silence_timer(self) -> None:
        engine = CIP5GSafetyURLLCEngine(auto_activate=True, watchdog_timeout_ms=10.0)

        # Advance 8 ms
        engine.scan_step(0.008)
        assert engine.is_healthy is True
        assert engine.silence_timer_ms == 8.0

        # Receive valid packet -> silence timer reset to 0
        pkt = engine.create_packet(seq=1)
        assert engine.process_packet(pkt) is True
        assert engine.silence_timer_ms == 0.0

        # Advance another 8 ms -> still healthy (only 8ms accumulated)
        engine.scan_step(0.008)
        assert engine.is_healthy is True

    def test_fault_injection_helpers(self) -> None:
        engine = CIP5GSafetyURLLCEngine(auto_activate=True)

        engine.inject_latency_overrun(15000)
        assert engine.diagnostic_code == DiagnosticCode.LATENCY_OVERRUN_TRIP
        assert engine.is_safe_stop_tripped is True

        engine.reset()
        engine.inject_packet_loss(2500)
        assert engine.diagnostic_code == DiagnosticCode.LATENCY_OVERRUN_TRIP

        engine.reset()
        engine.inject_watchdog_timeout()
        assert engine.diagnostic_code == DiagnosticCode.LATENCY_OVERRUN_TRIP


# ============================================================================
# 7. TestEpidAuthenticationAndSecurity
# ============================================================================

class TestEpidAuthenticationAndSecurity:
    """Validate EPID authentication, sequence diversion, and CRC fault interception (0xEE24)."""

    def test_authorized_epid_accepted(self) -> None:
        engine = CIP5GSafetyURLLCEngine(auto_activate=True)
        pkt = engine.create_packet(seq=1)
        assert engine.process_packet(pkt) is True
        assert engine.is_healthy is True

    def test_unauthorized_rogue_epid_trips_auth_fail(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)

        # Rogue device with foreign EPID
        rogue_pkt = create_valid_5g_safety_packet(
            sequence_primary=2,
            epid="ROGUE-5G-DEVICE-HIJACK",
        )
        assert engine.process_packet(rogue_pkt) is False
        assert engine.state == Safe5GState.URLLC_TIMEOUT_SAFE_STOP
        assert engine.diagnostic_code == DiagnosticCode.AUTH_FAIL_TRIP
        assert engine.diagnostic_code == 0xEE24
        assert rt.read_word("%R2170") == 4
        assert rt.read_uword("%R2177") == 0xEE24
        assert rt.read_bit("%M506") is False
        assert rt.read_bit("%M507") is True

    def test_corrupted_sequence_diversion_trips_auth_fail(self) -> None:
        engine = CIP5GSafetyURLLCEngine(auto_activate=True)
        pkt = engine.create_packet(seq=3)
        # Invalidate diversified sequence property
        pkt.sequence_diversified = pkt.sequence_primary
        # Recompute CRCs so CRCs match the corrupted sequence
        pkt.calculate_crcs()

        assert engine.process_packet(pkt) is False
        assert engine.diagnostic_code == DiagnosticCode.AUTH_FAIL_TRIP
        assert engine.is_safe_stop_tripped is True

    def test_corrupted_crc_trips_auth_fail(self) -> None:
        engine = CIP5GSafetyURLLCEngine(auto_activate=True)
        pkt = engine.create_packet(seq=4)
        # Corrupt CRC-S1
        pkt.crc_s1 ^= 0x1234

        assert engine.process_packet(pkt) is False
        assert engine.diagnostic_code == DiagnosticCode.AUTH_FAIL_TRIP
        assert engine.is_safe_stop_tripped is True

    def test_inject_auth_failure_helper(self) -> None:
        engine = CIP5GSafetyURLLCEngine(auto_activate=True)
        engine.inject_auth_failure()
        assert engine.diagnostic_code == DiagnosticCode.AUTH_FAIL_TRIP
        assert engine.is_safe_stop_tripped is True


# ============================================================================
# 8. TestRegisterSynchronization
# ============================================================================

class TestRegisterSynchronization:
    """Validate bit-exact Horner OCS register synchronization (%R2170..%R2177, %M506..%M507)."""

    def test_initial_synchronization(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)

        assert rt.read_word("%R2170") == 3
        assert rt.read_word("%R2171") == -75
        assert rt.read_word("%R2172") == 18
        assert rt.read_word("%R2173") == 950
        assert rt.read_uword("%R2174") == 1
        assert rt.read_uword("%R2175") == 82
        assert rt.read_uword("%R2176") == 0
        assert rt.read_uword("%R2177") == 0x0000
        assert rt.read_bit("%M506") is True
        assert rt.read_bit("%M507") is False

    def test_handover_count_synchronization(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)

        assert engine.trigger_handover() == 1
        assert rt.read_uword("%R2176") == 1

        assert engine.trigger_handover() == 2
        assert rt.read_uword("%R2176") == 2

    def test_transmit_packet_statistics(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)

        pkt1 = engine.transmit_packet()
        assert pkt1.sequence_primary == 1
        assert engine.packets_transmitted == 1
        assert engine.transmit_sequence == 1

        pkt2 = engine.transmit_packet()
        assert pkt2.sequence_primary == 2
        assert engine.packets_transmitted == 2
        assert engine.transmit_sequence == 2

    def test_all_trip_codes_reflection(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)

        trips = [
            (DiagnosticCode.RSRP_DROP_TRIP, 0xEE21),
            (DiagnosticCode.SINR_NOISE_TRIP, 0xEE22),
            (DiagnosticCode.LATENCY_OVERRUN_TRIP, 0xEE23),
            (DiagnosticCode.AUTH_FAIL_TRIP, 0xEE24),
        ]

        for code, expected_hex in trips:
            engine.trip_fault(code)
            assert rt.read_word("%R2170") == 4
            assert rt.read_uword("%R2177") == expected_hex
            assert rt.read_bit("%M506") is False
            assert rt.read_bit("%M507") is True

            engine.reset()
            assert rt.read_word("%R2170") == 3
            assert rt.read_uword("%R2177") == 0x0000
            assert rt.read_bit("%M506") is True
            assert rt.read_bit("%M507") is False

    def test_safe_write_wrappers(self) -> None:
        rt = RegisterTable()
        # Word wrapping test (> 32767 wraps to negative)
        safe_write_word(rt, "%R2170", 40000)
        assert rt.read_word("%R2170") == 40000 - 65536

        # UWord test
        safe_write_uword(rt, "%R2177", 0xEE21)
        assert rt.read_uword("%R2177") == 0xEE21

        # Bit test
        safe_write_bit(rt, "%M506", True)
        assert rt.read_bit("%M506") is True
        safe_write_bit(rt, "%M506", False)
        assert rt.read_bit("%M506") is False


# ============================================================================
# 9. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 ST POU verification with SecurityGuard and STParser."""

    def test_pure_st_pou_verification(self) -> None:
        assert verify_cip_safety_5g_urllc_pure_st() is True
        assert verify_cip_safety_5g_urllc_pure_st(CIP_SAFETY_5G_URLLC_PURE_ST_POU) is True
        assert verify_cip_safety_5g_urllc_pure_st(CIP_SAFETY_5G_URLLC_SYNC_POU) is True
        assert verify_cip_safety_5g_urllc_pure_st(CIP_SAFETY_5G_URLLC_POU) is True
        assert verify_cip_safety_5g_urllc_pure_st(CIP_SAFETY_5G_POU) is True
        assert verify_cip_safety_5g_urllc_pure_st(PURE_ST_POU) is True
        assert verify_cip_safety_5g_urllc_pure_st(CipSafety5GUrllcSync) is True
        assert verify_cip_safety_5g_urllc_pure_st(CipSafety5GUrllcSyncPOU) is True
        assert verify_cip_safety_5g_urllc_pure_st(CipSafety5gUrllcSync) is True

    def test_security_guard_and_st_parser(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_5G_URLLC_PURE_ST_POU)
        res = STParser.validate_code(CIP_SAFETY_5G_URLLC_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(CIP_SAFETY_5G_URLLC_PURE_ST_POU)
        assert ast.pou_type == POUType.PROGRAM
        expected_regs = {
            "%R2170", "%R2171", "%R2172", "%R2173",
            "%R2174", "%R2175", "%R2176", "%R2177",
            "%M506", "%M507",
        }
        assert expected_regs.issubset(set(ast.bound_registers))


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
            "OTE(Coil1);",
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
        engine = CIP5GSafetyURLLCEngine(auto_activate=True)
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "CIP5GSafetyURLLCEngine"
        assert engine.priority == 10
        assert engine.is_enabled is True
        assert engine.is_healthy is True
        assert engine.link_healthy is True
        assert engine.is_safe_stop_tripped is False
        assert engine.safe_stop_tripped is False
        assert engine.state == Safe5GState.AUTHENTICATED_OPERATIONAL

    def test_scan_step_and_step(self) -> None:
        engine = CIP5GSafetyURLLCEngine(auto_activate=True)
        assert engine.cycles_count == 0
        engine.scan_step(0.005)
        assert engine.cycles_count == 1

        engine.step(0.005)
        assert engine.cycles_count == 2

    def test_execute_scan_context(self) -> None:
        engine = CIP5GSafetyURLLCEngine(auto_activate=True)
        ctx = ScanContext(cycle=1, dt_ms=5.0)
        engine.execute(ctx)
        assert engine.cycles_count == 1

    def test_100_cycle_soak_stability(self) -> None:
        rt = RegisterTable()
        engine = CIP5GSafetyURLLCEngine(register_table=rt, auto_activate=True)

        tracemalloc.start()
        snapshot_before = tracemalloc.take_snapshot()

        for cycle_i in range(1, 101):
            pkt = engine.create_packet(seq=cycle_i)
            assert engine.process_packet(pkt) is True
            engine.scan_step(0.005)

        snapshot_after = tracemalloc.take_snapshot()
        stats = snapshot_after.compare_to(snapshot_before, "lineno")
        heap_growth_kb = sum(st.size_diff for st in stats if st.size_diff > 0) / 1024.0
        tracemalloc.stop()

        assert engine.cycles_count == 100
        assert engine.packets_processed == 100
        assert engine.is_healthy is True
        assert engine.is_safe_stop_tripped is False
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert heap_growth_kb < 100.0  # Zero leak tolerance


# ============================================================================
# 12. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Verify 10-stage verification suite export, strict 4-state contract, and exception hierarchy."""

    def test_runner_returns_success(self, tmp_path: Path) -> None:
        out_file = tmp_path / "cip_safety_5g_urllc_evidence.json"
        res = run_cip_safety_5g_urllc_verification(output_path=str(out_file), work_package="W256")

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["work_package"] == "W256"
        assert res["stages_passed"] == 10
        assert res["total_stages"] == 10
        assert out_file.exists()

        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["stages_passed"] == 10
        assert len(data["data"]["stages"]) == 10
        assert data["data"]["protocol"] == "ODVA CIP Safety Over 5G URLLC (3GPP Rel 16/17)"

    def test_exception_inheritance(self) -> None:
        assert issubclass(CIP5GRsrpDropError, CIP5GSafetyError)
        assert issubclass(CIP5GSinrNoiseError, CIP5GSafetyError)
        assert issubclass(CIP5GLatencyOverrunError, CIP5GSafetyError)
        assert issubclass(CIP5GAuthenticationError, CIP5GSafetyError)
        assert issubclass(CIP5GWatchdogTimeoutError, CIP5GSafetyError)
        assert issubclass(CIP5GCrcFaultError, CIP5GSafetyError)

        assert issubclass(URLLCRsrpDropError, CIP5GURLLCSafetyError)
        assert issubclass(URLLCSinrInterferenceError, CIP5GURLLCSafetyError)
        assert issubclass(URLLCLatencyOverrunError, CIP5GURLLCSafetyError)
        assert issubclass(URLLCAuthenticationError, CIP5GURLLCSafetyError)
        assert issubclass(URLLCWatchdogTimeoutError, CIP5GURLLCSafetyError)
        assert issubclass(URLLCCrcFaultError, CIP5GURLLCSafetyError)

    def test_engine_class_aliases(self) -> None:
        assert CipSafety5GUrllcEngine == CIP5GSafetyURLLCEngine
        assert CIP5GSafetyEngine == CIP5GSafetyURLLCEngine
        assert CIPSafety5GUrllcEngine == CIP5GSafetyURLLCEngine
        assert CIP_SAFETY_5G_URLLC_ENGINE == CIP5GSafetyURLLCEngine
        assert CIP5GURLLCSafetyEngine == CIP5GSafetyURLLCEngine
        assert CIP5GSafetyPacket == CIP5GSafetyURLLCPacket
        assert CipSafety5GUrllcPacket == CIP5GSafetyURLLCPacket
        assert CIP5GURLLCSafetyPacket == CIP5GSafetyURLLCPacket
