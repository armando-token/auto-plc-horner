"""Comprehensive Unit Test Suite for Wave W244 CIP Safety Time-Synchronized Bridge.

Work Package: W244 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Protocol: Industrial ODVA CIP Safety Time-Synchronized IEEE 1588 CIP Sync Safety Bridge.

Covers 120+ Deterministic Unit Tests across 12 Mandatory Test Classes:
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned 16-bit equality, hashing, enums, register names, coil addresses.
2. TestCipSafetySyncConfiguration: SNN, SCID, Grandmaster clock status, 4 node registration, EPI (10ms), watchdog (30ms).
3. TestCrcSChecksumAlgorithms: CRC-S1 (0x5935) and CRC-S2 (0x755B) deterministic calculation, single-bit corruption detection.
4. TestDualChannelParityAndDiscrepancy: Complement parity validation, discrepancy injection.
5. TestEpiWatchdogSurveillance: Watchdog timer countdown, 0xEC02 timeout injection, %M479 trip.
6. TestClockDriftAndJitterSurveillance: Drift > 5.0 ppm trips 0xEC03, timestamp jitter > 1000 ns trips 0xEC04.
7. TestGrandmasterLossAndNodeDisconnect: Grandmaster loss 0xEC05, node disconnect 0xEC06, safe state latching, recovery resets.
8. TestHornerOCSSynchronizationAndRegisters: %R2050..%R2057 and %M478..%M479 bit-exact synchronization, PrivilegeMode.SYSTEM.
9. TestPureSTAndSecurity: STParser & SecurityGuard verification of CipSafetySyncBridgeSync POU.
10. TestAntiLadderRejection: Rejection of 6+ ladder constructs (contacts `---[ ]---`, coils `---( )---`, rungs, networks, mnemonics) with LadderForbiddenError.
11. TestILogicUnitCompliance: scan_step, step, execute, reset, 100-cycle soak stability.
12. TestVerificationRunnerAndContract: Deterministic 9-stage runner export and strict 4-state contract validation.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_safety_sync import (
    CIP_SAFETY_CONNECTION_CLASS_ID,
    CIP_SAFETY_CRC_INIT,
    CIP_SAFETY_CRC_S1_POLY,
    CIP_SAFETY_CRC_S2_POLY,
    CIP_SAFETY_SUPERVISOR_CLASS_ID,
    CIP_SAFETY_SYNC_BRIDGE_CLASS_ID,
    CIP_SAFETY_SYNC_BRIDGE_SYNC_POU,
    CIP_SAFETY_SYNC_POU,
    CIP_SAFETY_VALIDATOR_CLASS_ID,
    CIP_SYNC_CLASS_ID,
    CIP_TIME_SYNC_CLASS_ID,
    CLOCK_DRIFT_SCALE_FACTOR,
    COIL_SAFETY_SYNC_ACTIVE,
    COIL_SAFETY_SYNC_FAULT_ACTIVE,
    CRC16_CCITT_INIT,
    CRC16_CCITT_POLY,
    CRC_S1_POLY,
    CRC_S2_POLY,
    CRC_S_INIT,
    DEFAULT_EPI_MS,
    DEFAULT_EPOCH_NS_BASE,
    DEFAULT_GM_IDENTITY,
    DEFAULT_MANAGED_NODES_COUNT,
    DEFAULT_SCID,
    DEFAULT_SCID_CRC,
    DEFAULT_SCID_TIMESTAMP,
    DEFAULT_SNN,
    DEFAULT_SYNCHRONIZED_NODES_COUNT,
    DEFAULT_WATCHDOG_MULTIPLIER,
    DEFAULT_WATCHDOG_TIMEOUT_MS,
    EPI_WATCHDOG_TIMEOUT_MS,
    MAX_CLOCK_DRIFT_PPM,
    MAX_SYNC_JITTER_NS,
    NOMINAL_CLOCK_DRIFT_PPM,
    NOMINAL_EPI_MS,
    NOMINAL_SYNC_JITTER_NS,
    REG_ACTIVE_DESYNC_NODE_INDEX,
    REG_CIP_SYNC_TOPOLOGY_STATUS_BITS,
    REG_CLOCK_DRIFT_OFFSET_PPM_SCALED,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_SELECTED_MONITORED_NODE,
    REG_SYNC_JITTER_MAX_NS,
    REG_SYNCHRONIZED_NODES_COUNT,
    REG_TIME_SYNC_MASTER_STATUS,
    WATCHDOG_MULTIPLIER,
    CIPSafetySyncEngine,
    CipSafetyClockDriftError,
    CipSafetyControlByte,
    CipSafetyCrcCorruptionError,
    CipSafetyCrcFaultError,
    CipSafetyDiagnosticCode,
    CipSafetyDiscrepancyError,
    CipSafetyEpiTimeoutError,
    CipSafetyGrandmasterLostError,
    CipSafetyNodeDisconnectError,
    CipSafetySyncBridge,
    CipSafetySyncBridgeEngine,
    CipSafetySyncEngine,
    CipSafetySyncError,
    CipSafetySyncPacket,
    CipSafetyTimestampJitterError,
    CipSyncDiagnosticCode,
    CipSyncTopologyStatusBits,
    CipTimeSyncObject,
    DiagnosticCode,
    DiagnosticStatusCode,
    DiversifiedMode,
    PtpTimestamp,
    SafetyConnectionObject,
    SafetyControlByte,
    SafetyNodeIndex,
    SafetyOperationalState,
    SafetySupervisorObject,
    SafetySyncBridgeEngine,
    SafetySyncState,
    SafetySyncStatusBits,
    SafetyValidatorObject,
    SynchronizedNodeIndex,
    SynchronizedSafetyNode,
    TopologyStatusBits,
    calc_crc_s1,
    calc_crc_s2,
    calculate_crc16_ccitt,
    compute_crc_s1,
    compute_crc_s2,
    create_valid_sync_packet,
    run_cip_safety_sync_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    scale_jitter_to_int16,
    scale_ppm_to_int16,
    verify_cip_safety_sync_pure_st,
    verify_dual_channel_payload,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate ODVA CIP Safety Volume 5 & CIP Sync constants, enums, register names, and diagnostic codes."""

    def test_class_ids(self) -> None:
        assert CIP_SAFETY_SUPERVISOR_CLASS_ID == 0x39
        assert CIP_SAFETY_VALIDATOR_CLASS_ID == 0x3A
        assert CIP_SAFETY_CONNECTION_CLASS_ID == 0x3B
        assert CIP_TIME_SYNC_CLASS_ID == 0x43
        assert CIP_SYNC_CLASS_ID == 0x43
        assert CIP_SAFETY_SYNC_BRIDGE_CLASS_ID == 0x3B

    def test_crc_polynomial_constants(self) -> None:
        assert CIP_SAFETY_CRC_S1_POLY == 0x5935
        assert CIP_SAFETY_CRC_S2_POLY == 0x755B
        assert CRC_S1_POLY == 0x5935
        assert CRC_S2_POLY == 0x755B
        assert CRC_S_INIT == 0xFFFF
        assert CIP_SAFETY_CRC_INIT == 0xFFFF
        assert CRC16_CCITT_POLY == 0x1021
        assert CRC16_CCITT_INIT == 0xFFFF

    def test_timing_and_drift_constants(self) -> None:
        assert NOMINAL_EPI_MS == 10.0
        assert DEFAULT_EPI_MS == 10.0
        assert WATCHDOG_MULTIPLIER == 3
        assert DEFAULT_WATCHDOG_MULTIPLIER == 3
        assert EPI_WATCHDOG_TIMEOUT_MS == 30.0
        assert DEFAULT_WATCHDOG_TIMEOUT_MS == 30.0
        assert NOMINAL_CLOCK_DRIFT_PPM == 1.20
        assert MAX_CLOCK_DRIFT_PPM == 5.00
        assert CLOCK_DRIFT_SCALE_FACTOR == 100.0
        assert NOMINAL_SYNC_JITTER_NS == 450
        assert MAX_SYNC_JITTER_NS == 1000
        assert DEFAULT_SYNCHRONIZED_NODES_COUNT == 4
        assert DEFAULT_MANAGED_NODES_COUNT == 4

    def test_register_and_coil_names(self) -> None:
        assert REG_TIME_SYNC_MASTER_STATUS == "%R2050"
        assert REG_CLOCK_DRIFT_OFFSET_PPM_SCALED == "%R2051"
        assert REG_SYNC_JITTER_MAX_NS == "%R2052"
        assert REG_SYNCHRONIZED_NODES_COUNT == "%R2053"
        assert REG_ACTIVE_DESYNC_NODE_INDEX == "%R2054"
        assert REG_CIP_SYNC_TOPOLOGY_STATUS_BITS == "%R2055"
        assert REG_SELECTED_MONITORED_NODE == "%R2056"
        assert REG_DIAGNOSTIC_STATUS_CODE == "%R2057"
        assert COIL_SAFETY_SYNC_ACTIVE == "%M478"
        assert COIL_SAFETY_SYNC_FAULT_ACTIVE == "%M479"

    def test_diagnostic_codes_unsigned_equality(self) -> None:
        assert DiagnosticCode.SYNC_OK == 0x0000
        assert DiagnosticCode.CRC_S_FAULT == 0xEC01
        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == 0xEC02
        assert DiagnosticCode.CLOCK_DRIFT_EXCEEDED == 0xEC03
        assert DiagnosticCode.TIMESTAMP_JITTER_FAULT == 0xEC04
        assert DiagnosticCode.GRANDMASTER_LOST == 0xEC05
        assert DiagnosticCode.SYNC_NODE_DISCONNECT == 0xEC06

    def test_diagnostic_codes_signed_equality(self) -> None:
        assert DiagnosticCode.SYNC_OK == 0
        assert DiagnosticCode.CRC_S_FAULT == -5119
        assert DiagnosticCode.EPI_WATCHDOG_TIMEOUT == -5118
        assert DiagnosticCode.CLOCK_DRIFT_EXCEEDED == -5117
        assert DiagnosticCode.TIMESTAMP_JITTER_FAULT == -5116
        assert DiagnosticCode.GRANDMASTER_LOST == -5115
        assert DiagnosticCode.SYNC_NODE_DISCONNECT == -5114

    def test_diagnostic_code_masking_with_0xffff(self) -> None:
        assert (DiagnosticCode.SYNC_OK & 0xFFFF) == 0x0000
        assert (DiagnosticCode.CRC_S_FAULT & 0xFFFF) == 0xEC01
        assert (DiagnosticCode.EPI_WATCHDOG_TIMEOUT & 0xFFFF) == 0xEC02
        assert (DiagnosticCode.CLOCK_DRIFT_EXCEEDED & 0xFFFF) == 0xEC03
        assert (DiagnosticCode.TIMESTAMP_JITTER_FAULT & 0xFFFF) == 0xEC04
        assert (DiagnosticCode.GRANDMASTER_LOST & 0xFFFF) == 0xEC05
        assert (DiagnosticCode.SYNC_NODE_DISCONNECT & 0xFFFF) == 0xEC06
        assert (0xFFFF & DiagnosticCode.CRC_S_FAULT) == 0xEC01
        assert isinstance(DiagnosticCode.CRC_S_FAULT & 0xFFFF, DiagnosticCode)

    def test_diagnostic_code_hashing_and_dict_keys(self) -> None:
        code = DiagnosticCode.CRC_S_FAULT
        code_timeout = DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        d: Dict[Any, str] = {code: "crc_err", code_timeout: "timeout_err"}
        assert d[0xEC01] == "crc_err"
        assert d[code] == "crc_err"
        assert d[0xEC02] == "timeout_err"
        assert d[code_timeout] == "timeout_err"
        assert hash(code) == hash(0xEC01)
        assert hash(code_timeout) == hash(0xEC02)
        assert code == -5119
        assert code_timeout == -5118

    def test_diagnostic_code_aliases(self) -> None:
        assert DiagnosticCode.OK == DiagnosticCode.SYNC_OK
        assert DiagnosticCode.NOMINAL == DiagnosticCode.SYNC_OK
        assert DiagnosticCode.CRC_FAULT == DiagnosticCode.CRC_S_FAULT
        assert DiagnosticCode.CRC_S_CORRUPTION == DiagnosticCode.CRC_S_FAULT
        assert DiagnosticCode.EPI_TIMEOUT == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert DiagnosticCode.CLOCK_DRIFT_FAULT == DiagnosticCode.CLOCK_DRIFT_EXCEEDED
        assert DiagnosticCode.JITTER_FAULT == DiagnosticCode.TIMESTAMP_JITTER_FAULT
        assert DiagnosticCode.TIMESTAMP_JITTER_EXCEEDED == DiagnosticCode.TIMESTAMP_JITTER_FAULT
        assert DiagnosticCode.GM_LOST == DiagnosticCode.GRANDMASTER_LOST
        assert DiagnosticCode.NODE_DISCONNECT == DiagnosticCode.SYNC_NODE_DISCONNECT
        assert DiagnosticCode.NODE_DESYNC == DiagnosticCode.SYNC_NODE_DISCONNECT
        assert DiagnosticCode.SYNC_NODE_DESYNC == DiagnosticCode.SYNC_NODE_DISCONNECT
        assert CipSafetyDiagnosticCode is DiagnosticCode
        assert CipSyncDiagnosticCode is DiagnosticCode
        assert DiagnosticStatusCode is DiagnosticCode

    def test_diagnostic_code_repr_and_str(self) -> None:
        code = DiagnosticCode.CRC_S_FAULT
        assert "0xEC01" in repr(code)
        assert "CRC_S_FAULT" in repr(code)
        assert "0xEC01" in str(code)
        assert int(code) == 0xEC01
        assert code.value == 0xEC01

    def test_topology_status_bitmask_flags(self) -> None:
        assert CipSyncTopologyStatusBits.GM_ACTIVE == 1 << 0
        assert CipSyncTopologyStatusBits.GM_SYNCHRONIZED == 1 << 1
        assert CipSyncTopologyStatusBits.ALL_NODES_SYNCED == 1 << 2
        assert CipSyncTopologyStatusBits.JITTER_HEALTHY == 1 << 3
        assert CipSyncTopologyStatusBits.DRIFT_HEALTHY == 1 << 4
        assert CipSyncTopologyStatusBits.NODE_0_SYNCED == 1 << 5
        assert CipSyncTopologyStatusBits.NODE_1_SYNCED == 1 << 6
        assert CipSyncTopologyStatusBits.NODE_2_SYNCED == 1 << 7
        assert CipSyncTopologyStatusBits.NODE_3_SYNCED == 1 << 8
        assert CipSyncTopologyStatusBits.DUAL_CHANNEL_VERIFIED == 1 << 9
        assert CipSyncTopologyStatusBits.CRC_VERIFIED == 1 << 10
        assert CipSyncTopologyStatusBits.EPI_WATCHDOG_OK == 1 << 11
        assert CipSyncTopologyStatusBits.TIME_STAMP_64BIT_VALID == 1 << 12
        assert CipSyncTopologyStatusBits.SAFETY_SYNC_ACTIVE == 1 << 13
        assert CipSyncTopologyStatusBits.FAULT_LATCH == 1 << 15
        assert TopologyStatusBits is CipSyncTopologyStatusBits
        assert SafetySyncStatusBits is CipSyncTopologyStatusBits

    def test_safety_control_byte_flags(self) -> None:
        assert SafetyControlByte.IDLE == 0x00
        assert SafetyControlByte.RUN == 1 << 0
        assert SafetyControlByte.PING_REQ == 1 << 1
        assert SafetyControlByte.PING_RESP == 1 << 2
        assert SafetyControlByte.SAFETY_DEMAND == 1 << 3
        assert SafetyControlByte.FAULT_PRESENT == 1 << 4
        assert SafetyControlByte.RESET_REQUEST == 1 << 5
        assert SafetyControlByte.SYNC_TIME_VALID == 1 << 6
        assert SafetyControlByte.DISCONNECT_REQ == 1 << 7
        assert CipSafetyControlByte is SafetyControlByte

    def test_safety_operational_state_enum(self) -> None:
        assert SafetyOperationalState.INITIALIZING == 0
        assert SafetyOperationalState.OPERATIONAL == 1
        assert SafetyOperationalState.DEGRADED == 2
        assert SafetyOperationalState.TRIPPED == 3
        assert SafetyOperationalState.SAFE_STATE == 4
        assert SafetySyncState is SafetyOperationalState

    def test_synchronized_node_index_enum(self) -> None:
        assert SynchronizedNodeIndex.NODE_0_PRESS_BRAKE == 0
        assert SynchronizedNodeIndex.NODE_1_PERIMETER_LASER == 1
        assert SynchronizedNodeIndex.NODE_2_TRANSFER_SHUTTLE == 2
        assert SynchronizedNodeIndex.NODE_3_COIL_FEEDER == 3
        assert SafetyNodeIndex is SynchronizedNodeIndex

    def test_exception_types_and_hierarchy(self) -> None:
        assert issubclass(CipSafetyCrcFaultError, CipSafetySyncError)
        assert issubclass(CipSafetyEpiTimeoutError, CipSafetySyncError)
        assert issubclass(CipSafetyClockDriftError, CipSafetySyncError)
        assert issubclass(CipSafetyTimestampJitterError, CipSafetySyncError)
        assert issubclass(CipSafetyGrandmasterLostError, CipSafetySyncError)
        assert issubclass(CipSafetyNodeDisconnectError, CipSafetySyncError)
        assert issubclass(CipSafetyDiscrepancyError, CipSafetySyncError)
        assert CipSafetyCrcCorruptionError is CipSafetyCrcFaultError


# ============================================================================
# 2. TestCipSafetySyncConfiguration
# ============================================================================

class TestCipSafetySyncConfiguration:
    """Validate SNN, SCID, Grandmaster clock status, 4 node registration, and EPI/Watchdog config."""

    def test_default_bridge_initialization(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        assert engine.is_active is True
        assert engine.is_fault_active is False
        assert engine.trip_safe_state_engaged is False
        assert engine.master_status == 1
        assert engine.grandmaster_active is True
        assert engine.grandmaster_synchronized is True
        assert engine.clock_drift_ppm == 1.20
        assert engine.sync_jitter_max_ns == 450.0
        assert engine.active_desync_node_index == -1
        assert engine.selected_monitored_node == 0
        assert engine.diagnostic_code == DiagnosticCode.SYNC_OK

    def test_snn_6_octet_default_format(self) -> None:
        engine = CipSafetySyncBridge()
        assert len(engine.snn) == 6
        assert engine.snn == DEFAULT_SNN
        assert engine.snn == bytes([0x20, 0x26, 0x10, 0x06, 0xEE, 0x88])

    def test_custom_snn_configuration(self) -> None:
        custom_snn = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        engine = CipSafetySyncBridge(snn=custom_snn)
        assert engine.snn == custom_snn
        assert engine.supervisor.snn == custom_snn

    def test_scid_constants_and_types(self) -> None:
        assert isinstance(DEFAULT_SCID, int)
        assert DEFAULT_SCID == 0x20261006
        assert DEFAULT_SCID_CRC == 0x20261006
        assert DEFAULT_SCID_TIMESTAMP == 0x10060003

    def test_grandmaster_clock_identity_and_defaults(self) -> None:
        engine = CipSafetySyncBridge()
        assert engine.grandmaster_identity == DEFAULT_GM_IDENTITY
        assert engine.grandmaster_identity == "00:1D:9C:FF:FE:C0:02:01"
        assert engine.time_sync.grandmaster_identity == DEFAULT_GM_IDENTITY
        assert engine.time_sync.grandmaster_clock_class == 6
        assert engine.time_sync.is_synchronized is True
        assert engine.time_sync.mean_path_delay_ns == 500

    def test_4_managed_synchronized_nodes_count_and_names(self) -> None:
        engine = CipSafetySyncBridge()
        assert len(engine.nodes) == 4
        assert engine.synchronized_nodes_count == 4
        assert engine.nodes[0].name == "Press Brake Safety Interlock"
        assert engine.nodes[1].name == "Perimeter Laser Scanner"
        assert engine.nodes[2].name == "Transfer Shuttle Muting"
        assert engine.nodes[3].name == "Coil Feeder Emergency Stop"

    def test_node_unids_and_initial_health(self) -> None:
        engine = CipSafetySyncBridge()
        expected_unids = [30, 31, 32, 33]
        for idx, (node, exp_unid) in enumerate(zip(engine.nodes, expected_unids)):
            assert node.node_index == idx
            assert node.node_id == idx
            assert node.unid == exp_unid
            assert node.is_connected is True
            assert node.is_synchronized is True
            assert node.is_faulted is False
            assert node.drift_ppm == 1.20
            assert node.jitter_ns == 450.0
            assert node.silence_time_ms == 0.0
            assert node.diagnostic_code == DiagnosticCode.SYNC_OK

    def test_node_to_dict_serialization(self) -> None:
        node = SynchronizedSafetyNode(
            node_index=1,
            name="Perimeter Laser Scanner",
            description="Zone monitor",
            unid=31,
        )
        d = node.to_dict()
        assert d["node_index"] == 1
        assert d["name"] == "Perimeter Laser Scanner"
        assert d["unid"] == 31
        assert d["is_connected"] is True
        assert d["is_synchronized"] is True
        assert d["is_faulted"] is False
        assert "SYNC_OK" in d["diagnostic_code"]

    def test_supervisor_and_validator_objects_state(self) -> None:
        engine = CipSafetySyncBridge()
        assert engine.supervisor.class_id == 0x39
        assert engine.supervisor.config_locked is False
        engine.supervisor.lock_configuration()
        assert engine.supervisor.config_locked is True
        engine.supervisor.unlock_configuration()
        assert engine.supervisor.config_locked is False

        assert engine.validator.class_id == 0x3A
        assert engine.validator.validation_errors == 0
        assert engine.validator.packets_validated == 0

        assert engine.connection.class_id == 0x3B
        assert engine.connection.is_established is True

    def test_ptp_timestamp_arithmetic_and_bounds(self) -> None:
        ts = PtpTimestamp(seconds=10, nanoseconds=500_000_000)
        assert ts.to_ns() == 10_500_000_000
        assert ts.to_float_seconds() == 10.5

        # Normalization with overflow nanoseconds
        ts_norm = PtpTimestamp(seconds=5, nanoseconds=1_500_000_000)
        assert ts_norm.seconds == 6
        assert ts_norm.nanoseconds == 500_000_000

        # Construct from float seconds
        ts_from_f = PtpTimestamp.from_float_seconds(12.25)
        assert ts_from_f.seconds == 12
        assert ts_from_f.nanoseconds == 250_000_000

        # Addition and subtraction
        ts_add = ts + 1_000_000_000
        assert ts_add.to_ns() == 11_500_000_000
        assert (ts_add - ts) == 1_000_000_000


# ============================================================================
# 3. TestCrcSChecksumAlgorithms
# ============================================================================

class TestCrcSChecksumAlgorithms:
    """Validate CRC-S1 (poly 0x5935) and CRC-S2 (poly 0x755B) deterministic computation & corruption detection."""

    def test_crc_s1_deterministic_vector(self) -> None:
        data = b"CIP_SAFETY_SYNC_TEST_VECTOR_1"
        crc1_first = compute_crc_s1(data)
        crc1_second = compute_crc_s1(data)
        assert crc1_first == crc1_second
        assert 0 <= crc1_first <= 0xFFFF
        assert crc1_first == calc_crc_s1(data)

    def test_crc_s2_deterministic_vector(self) -> None:
        data = b"CIP_SAFETY_SYNC_TEST_VECTOR_1"
        crc2_first = compute_crc_s2(data)
        crc2_second = compute_crc_s2(data)
        assert crc2_first == crc2_second
        assert 0 <= crc2_first <= 0xFFFF
        assert crc2_first == calc_crc_s2(data)

    def test_crc_s1_and_s2_poly_differences(self) -> None:
        data = b"CIP_SAFETY_SYNC_FRAME_DATA"
        crc1 = compute_crc_s1(data)
        crc2 = compute_crc_s2(data)
        # Generators 0x5935 and 0x755B are distinct; outputs must differ
        assert crc1 != crc2

    def test_crc_s1_single_bit_flip_payload(self) -> None:
        data = bytearray(b"SAFETY_FRAME_PAYLOAD_001")
        orig_crc = compute_crc_s1(bytes(data))
        data[0] ^= 0x01  # Flip 1 bit
        corrupted_crc = compute_crc_s1(bytes(data))
        assert orig_crc != corrupted_crc

    def test_crc_s2_single_bit_flip_payload(self) -> None:
        data = bytearray(b"SAFETY_FRAME_PAYLOAD_002")
        orig_crc = compute_crc_s2(bytes(data))
        data[5] ^= 0x08  # Flip 1 bit
        corrupted_crc = compute_crc_s2(bytes(data))
        assert orig_crc != corrupted_crc

    def test_crc_s1_single_bit_flip_timestamp(self) -> None:
        ts = DEFAULT_EPOCH_NS_BASE
        seq = 100
        payload = bytes([0xAA, 0x55])
        orig_crc = compute_crc_s1(ts, seq, payload)
        # Flip 1 bit in timestamp
        corrupted_ts = ts ^ (1 << 16)
        corrupted_crc = compute_crc_s1(corrupted_ts, seq, payload)
        assert orig_crc != corrupted_crc

    def test_crc_s2_single_bit_flip_sequence(self) -> None:
        ts = DEFAULT_EPOCH_NS_BASE
        seq = 100
        payload = bytes([0xAA, 0x55])
        orig_crc = compute_crc_s2(ts, seq, payload)
        # Flip 1 bit in sequence number
        corrupted_seq = seq ^ 0x0001
        corrupted_crc = compute_crc_s2(ts, corrupted_seq, payload)
        assert orig_crc != corrupted_crc

    def test_crc_s_packet_protected_bytes_structure(self) -> None:
        pkt = CipSafetySyncPacket(
            snn=DEFAULT_SNN,
            source_node_index=2,
            sequence_number=42,
            timestamp_ns=1_700_000_000_123_456_789,
            mode_byte=SafetyControlByte.RUN,
            channel_a_payload=bytes([0x12, 0x34]),
        )
        prot = pkt.get_protected_bytes()
        assert len(prot) == 6 + 1 + 1 + 2 + 8 + 2
        assert prot[:6] == DEFAULT_SNN
        assert prot[6] == 2
        assert prot[7] == int(SafetyControlByte.RUN)
        seq_unpacked, ts_unpacked = struct.unpack(">HQ", prot[8:18])
        assert seq_unpacked == 42
        assert ts_unpacked == 1_700_000_000_123_456_789
        assert prot[18:] == bytes([0x12, 0x34])

    def test_packet_verify_crcs_deterministic(self) -> None:
        pkt = create_valid_sync_packet(node_index=0, sequence_number=10)
        assert pkt.crc_s1 != 0
        assert pkt.crc_s2 != 0
        assert pkt.verify_crcs() is True

    def test_packet_verify_crcs_bit_corruption_rejection(self) -> None:
        pkt = create_valid_sync_packet(node_index=0, sequence_number=10)
        assert pkt.verify_crcs() is True

        # Corrupt CRC-S1
        pkt.crc_s1 ^= 0x0001
        assert pkt.verify_crcs() is False
        pkt.crc_s1 ^= 0x0001  # Restore

        # Corrupt CRC-S2
        pkt.crc_s2 ^= 0x0080
        assert pkt.verify_crcs() is False

    def test_compute_crc_argument_handling(self) -> None:
        # Tuple arguments (ts, seq, payload)
        crc1 = compute_crc_s1(100, 1, bytes([0x01]))
        assert isinstance(crc1, int)
        # Multiple byte buffers
        crc2 = compute_crc_s1(b"PART1", b"PART2")
        assert crc2 == compute_crc_s1(b"PART1PART2")
        # Invalid arguments raise ValueError
        with pytest.raises(ValueError, match="Unsupported arguments"):
            compute_crc_s1(None)

    def test_crc_s_empty_and_short_payloads(self) -> None:
        crc1_empty = compute_crc_s1(b"")
        crc2_empty = compute_crc_s2(b"")
        assert crc1_empty == 0xFFFF
        assert crc2_empty == 0xFFFF
        crc1_one = compute_crc_s1(b"\x00")
        assert crc1_one != 0xFFFF


# ============================================================================
# 4. TestDualChannelParityAndDiscrepancy
# ============================================================================

class TestDualChannelParityAndDiscrepancy:
    """Validate complementary parity validation (~Channel A) and discrepancy injection detection."""

    def test_verify_dual_channel_inverted_bytes(self) -> None:
        ch_a = bytes([0x01, 0x00, 0x55, 0xAA])
        ch_b = bytes([0xFE, 0xFF, 0xAA, 0x55])
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is True

    def test_verify_dual_channel_inverted_integers(self) -> None:
        val_a = 0x1234
        val_b = (~val_a) & 0xFFFF
        assert verify_dual_channel_payload(val_a, val_b, DiversifiedMode.INVERTED) is True

    def test_verify_dual_channel_identical_mode(self) -> None:
        ch_a = bytes([0x12, 0x34])
        ch_b = bytes([0x12, 0x34])
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.IDENTICAL) is True
        assert verify_dual_channel_payload(0x1234, 0x1234, DiversifiedMode.IDENTICAL) is True

    def test_verify_dual_channel_discrepancy_flip_one_bit(self) -> None:
        ch_a = bytes([0x01, 0x00])
        ch_b = bytearray([0xFE, 0xFF])
        ch_b[0] ^= 0x01  # Corrupt 1 bit in channel B
        assert verify_dual_channel_payload(ch_a, bytes(ch_b), DiversifiedMode.INVERTED) is False

    def test_verify_dual_channel_length_mismatch(self) -> None:
        ch_a = bytes([0x01, 0x00])
        ch_b = bytes([0xFE, 0xFF, 0x00])
        assert verify_dual_channel_payload(ch_a, ch_b, DiversifiedMode.INVERTED) is False

    def test_verify_dual_channel_type_mismatch(self) -> None:
        assert verify_dual_channel_payload("invalid", "invalid") is False

    def test_packet_dual_channel_verification_method(self) -> None:
        pkt = create_valid_sync_packet(node_index=1, channel_a_payload=bytes([0xAB, 0xCD]))
        assert pkt.verify_dual_channel(DiversifiedMode.INVERTED) is True
        # Alter channel B
        pkt.channel_b_payload = bytes([0x00, 0x00])
        assert pkt.verify_dual_channel(DiversifiedMode.INVERTED) is False

    def test_engine_process_packet_discrepancy_raises_error(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        pkt = create_valid_sync_packet(node_index=2, channel_a_payload=bytes([0x10, 0x20]))
        # Corrupt channel B without corrupting CRC (simulate hardware fault)
        pkt.channel_b_payload = bytes([0x10, 0x20])  # Non-complementary
        pkt.calculate_crcs()  # CRC matches new payload but dual channel is discrepant

        with pytest.raises(CipSafetyDiscrepancyError, match="Dual-channel discrepancy"):
            engine.process_packet(pkt)

        assert engine.is_fault_active is True
        assert engine.is_active is False
        assert engine.diagnostic_code == DiagnosticCode.CRC_S_FAULT
        assert engine.validator.validation_errors >= 1

    def test_engine_process_packet_discrepancy_recovery_after_reset(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        pkt_bad = create_valid_sync_packet(node_index=0)
        pkt_bad.channel_b_payload = bytes([0x00, 0x00])
        pkt_bad.calculate_crcs()

        try:
            engine.process_packet(pkt_bad)
        except CipSafetyDiscrepancyError:
            pass

        assert engine.is_fault_active is True
        assert rt.read_bit("%M479") is True

        # Reset engine and send valid packet
        engine.reset()
        assert engine.is_fault_active is False
        assert rt.read_bit("%M479") is False

        pkt_good = create_valid_sync_packet(node_index=0)
        assert engine.process_packet(pkt_good) is True
        assert engine.is_fault_active is False


# ============================================================================
# 5. TestEpiWatchdogSurveillance
# ============================================================================

class TestEpiWatchdogSurveillance:
    """Validate Expected Packet Interval (EPI) surveillance, countdown, timeout injection (0xEC02) and %M479 trip."""

    def test_watchdog_silence_accumulation_on_scan(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        assert engine.nodes[0].silence_time_ms == 0.0
        engine.scan_step(0.010)
        assert abs(engine.nodes[0].silence_time_ms - 10.0) < 1e-4
        engine.scan_step(0.010)
        assert abs(engine.nodes[0].silence_time_ms - 20.0) < 1e-4

    def test_watchdog_silence_cleared_by_valid_packet(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        engine.scan_step(0.020)
        assert abs(engine.nodes[1].silence_time_ms - 20.0) < 1e-4

        pkt = create_valid_sync_packet(node_index=1)
        engine.process_packet(pkt)
        assert engine.nodes[1].silence_time_ms == 0.0

    def test_watchdog_within_30ms_does_not_trip(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.scan_step(0.010)
        engine.scan_step(0.010)
        assert engine.is_active is True
        assert engine.is_fault_active is False
        assert engine.diagnostic_code == DiagnosticCode.SYNC_OK
        assert rt.read_bit("%M478") is True
        assert rt.read_bit("%M479") is False

    def test_watchdog_silence_over_30ms_trips_0xec02(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.scan_step(0.020)
        engine.scan_step(0.015)  # Total 35 ms > 30 ms
        assert engine.is_active is False
        assert engine.is_fault_active is True
        assert engine.trip_safe_state_engaged is True
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert rt.read_uword("%R2057") == 0xEC02
        assert rt.read_word("%R2057") == -5118

    def test_watchdog_trip_deenergizes_coil_m478(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.scan_step(0.035)
        assert rt.read_bit("%M478") is False

    def test_watchdog_trip_energizes_coil_m479(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.scan_step(0.035)
        assert rt.read_bit("%M479") is True

    def test_watchdog_trip_marks_node_faulted(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        engine.scan_step(0.035)
        assert engine.nodes[0].is_faulted is True
        assert engine.nodes[0].diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT
        assert engine.nodes[0].consecutive_faults >= 1

    def test_watchdog_custom_timeout_configuration(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True, watchdog_timeout_ms=50.0)
        engine.scan_step(0.035)  # 35 ms silence: healthy with 50 ms limit
        assert engine.is_fault_active is False
        engine.scan_step(0.020)  # Total 55 ms > 50 ms
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT

    def test_watchdog_latched_behavior_across_subsequent_scans(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        engine.scan_step(0.035)
        assert engine.is_fault_active is True
        # Subsequent steps must remain faulted
        engine.scan_step(0.010)
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.EPI_WATCHDOG_TIMEOUT


# ============================================================================
# 6. TestClockDriftAndJitterSurveillance
# ============================================================================

class TestClockDriftAndJitterSurveillance:
    """Validate clock drift (> 5.0 ppm trips 0xEC03) and timestamp jitter (> 1000 ns trips 0xEC04)."""

    def test_nominal_drift_and_jitter_no_trip(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        assert engine.clock_drift_ppm == 1.20
        assert engine.sync_jitter_max_ns == 450.0
        assert rt.read_word("%R2051") == 120
        assert rt.read_word("%R2052") == 450
        assert engine.is_fault_active is False

    def test_drift_scaling_helper_function(self) -> None:
        assert scale_ppm_to_int16(1.20) == 120
        assert scale_ppm_to_int16(5.00) == 500
        assert scale_ppm_to_int16(5.50) == 550
        assert scale_ppm_to_int16(-1.20) == -120

    def test_jitter_scaling_helper_function(self) -> None:
        assert scale_jitter_to_int16(450.0) == 450
        assert scale_jitter_to_int16(1000.0) == 1000
        assert scale_jitter_to_int16(1250.0) == 1250

    def test_clock_drift_exceeded_trips_0xec03(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.inject_drift(5.50)  # > 5.00 ppm limit
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.CLOCK_DRIFT_EXCEEDED
        assert rt.read_word("%R2051") == 550
        assert rt.read_uword("%R2057") == 0xEC03
        assert rt.read_word("%R2057") == -5117
        assert rt.read_bit("%M478") is False
        assert rt.read_bit("%M479") is True

    def test_clock_drift_boundary_condition(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        engine.inject_drift(5.00)  # Exact boundary
        assert engine.is_fault_active is False
        engine.inject_drift(5.01)  # Just over limit
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.CLOCK_DRIFT_EXCEEDED

    def test_clock_drift_register_r2051_scaled_sync(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.inject_drift(2.75)
        assert rt.read_word("%R2051") == 275

    def test_timestamp_jitter_exceeded_trips_0xec04(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.inject_jitter(1250.0)  # > 1000 ns limit
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.TIMESTAMP_JITTER_FAULT
        assert rt.read_word("%R2052") == 1250
        assert rt.read_uword("%R2057") == 0xEC04
        assert rt.read_word("%R2057") == -5116
        assert rt.read_bit("%M478") is False
        assert rt.read_bit("%M479") is True

    def test_timestamp_jitter_boundary_condition(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        engine.inject_jitter(1000.0)  # Exact boundary
        assert engine.is_fault_active is False
        engine.inject_jitter(1001.0)  # Just over limit
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.TIMESTAMP_JITTER_FAULT

    def test_timestamp_jitter_register_r2052_sync(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.inject_jitter(850.0)
        assert rt.read_word("%R2052") == 850

    def test_scan_step_detects_drift_and_jitter_trips(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        engine.clock_drift_ppm = 6.00  # Set without immediate inject
        engine.scan_step(0.010)
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.CLOCK_DRIFT_EXCEEDED


# ============================================================================
# 7. TestGrandmasterLossAndNodeDisconnect
# ============================================================================

class TestGrandmasterLossAndNodeDisconnect:
    """Validate Grandmaster loss (0xEC05), node disconnect (0xEC06), latching, and recovery resets."""

    def test_grandmaster_nominal_status(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        assert engine.master_status == 1
        assert engine.grandmaster_active is True
        assert engine.grandmaster_synchronized is True
        assert engine.time_sync.is_synchronized is True

    def test_lose_grandmaster_trips_0xec05(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.lose_grandmaster()
        assert engine.master_status == 0
        assert engine.grandmaster_active is False
        assert engine.grandmaster_synchronized is False
        assert engine.time_sync.is_synchronized is False
        assert engine.is_active is False
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.GRANDMASTER_LOST
        assert rt.read_word("%R2050") == 0
        assert rt.read_uword("%R2057") == 0xEC05
        assert rt.read_word("%R2057") == -5115
        assert rt.read_bit("%M478") is False
        assert rt.read_bit("%M479") is True

    def test_disconnect_node_trips_0xec06(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.disconnect_node(1)  # Perimeter Laser Scanner
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.SYNC_NODE_DISCONNECT
        assert engine.active_desync_node_index == 1
        assert rt.read_word("%R2054") == 1
        assert rt.read_uword("%R2057") == 0xEC06
        assert rt.read_word("%R2057") == -5114

    def test_disconnect_node_decrements_synchronized_nodes_count_r2053(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        assert engine.synchronized_nodes_count == 4
        engine.disconnect_node(2)  # Transfer Shuttle Muting
        assert engine.synchronized_nodes_count == 3
        assert rt.read_word("%R2053") == 3

    def test_desync_node_behavior(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.desync_node(3)  # Coil Feeder
        assert engine.nodes[3].is_synchronized is False
        assert engine.diagnostic_code == DiagnosticCode.SYNC_NODE_DISCONNECT
        assert engine.active_desync_node_index == 3
        assert rt.read_word("%R2054") == 3

    def test_safe_state_latching_remains_tripped(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        engine.disconnect_node(0)
        assert engine.trip_safe_state_engaged is True
        engine.scan_step(0.010)
        assert engine.is_fault_active is True
        assert engine.diagnostic_code == DiagnosticCode.SYNC_NODE_DISCONNECT

    def test_operator_reset_recovers_from_gm_loss(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.lose_grandmaster()
        assert engine.is_fault_active is True
        assert rt.read_bit("%M479") is True

        engine.reset()
        assert engine.is_fault_active is False
        assert engine.is_active is True
        assert engine.master_status == 1
        assert engine.diagnostic_code == DiagnosticCode.SYNC_OK
        assert rt.read_word("%R2050") == 1
        assert rt.read_uword("%R2057") == 0x0000
        assert rt.read_bit("%M478") is True
        assert rt.read_bit("%M479") is False

    def test_operator_reset_recovers_from_node_disconnect(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.disconnect_node(2)
        assert engine.synchronized_nodes_count == 3

        engine.reset()
        assert engine.synchronized_nodes_count == 4
        assert engine.active_desync_node_index == -1
        assert rt.read_word("%R2053") == 4
        assert rt.read_word("%R2054") == -1
        assert rt.read_uword("%R2057") == 0x0000

    def test_operator_reset_resets_all_4_nodes(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        engine.nodes[0].is_faulted = True
        engine.nodes[1].is_connected = False
        engine.nodes[2].is_synchronized = False
        engine.reset()
        for n in engine.nodes:
            assert n.is_connected is True
            assert n.is_synchronized is True
            assert n.is_faulted is False

    def test_out_of_bounds_node_index_handling(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        # Invalid index 99 does not crash
        engine.disconnect_node(99)
        assert engine.is_fault_active is False


# ============================================================================
# 8. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate Horner OCS %R2050..%R2057 and %M478..%M479 bit-exact register synchronization."""

    def test_register_table_initial_nominal_mapping(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        assert rt.read_word("%R2050") == 1
        assert rt.read_word("%R2051") == 120
        assert rt.read_word("%R2052") == 450
        assert rt.read_word("%R2053") == 4
        assert rt.read_word("%R2054") == -1
        assert rt.read_word("%R2056") == 0
        assert rt.read_uword("%R2057") == 0x0000
        assert rt.read_word("%R2057") == 0

    def test_coils_initial_nominal_mapping(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        assert rt.read_bit("%M478") is True
        assert rt.read_bit("%M479") is False

    def test_safe_write_word_signed_wrapping(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R2057", 0xEC01)
        assert rt.read_word("%R2057") == -5119
        assert rt.read_uword("%R2057") == 0xEC01

    def test_safe_write_uword_helper(self) -> None:
        rt = RegisterTable()
        safe_write_uword(rt, "%R2057", 0xEC02)
        assert rt.read_uword("%R2057") == 0xEC02
        assert rt.read_word("%R2057") == -5118

    def test_safe_write_bit_system_privilege(self) -> None:
        rt = RegisterTable()
        safe_write_bit(rt, "%M478", True)
        assert rt.read_bit("%M478") is True
        safe_write_bit(rt, "%M478", False)
        assert rt.read_bit("%M478") is False

    def test_topology_status_bits_calculation_nominal(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        bits = engine.topology_status_bits
        assert (bits & CipSyncTopologyStatusBits.GM_ACTIVE) != 0
        assert (bits & CipSyncTopologyStatusBits.GM_SYNCHRONIZED) != 0
        assert (bits & CipSyncTopologyStatusBits.ALL_NODES_SYNCED) != 0
        assert (bits & CipSyncTopologyStatusBits.JITTER_HEALTHY) != 0
        assert (bits & CipSyncTopologyStatusBits.DRIFT_HEALTHY) != 0
        assert (bits & CipSyncTopologyStatusBits.NODE_0_SYNCED) != 0
        assert (bits & CipSyncTopologyStatusBits.NODE_1_SYNCED) != 0
        assert (bits & CipSyncTopologyStatusBits.NODE_2_SYNCED) != 0
        assert (bits & CipSyncTopologyStatusBits.NODE_3_SYNCED) != 0
        assert (bits & CipSyncTopologyStatusBits.SAFETY_SYNC_ACTIVE) != 0
        assert (bits & CipSyncTopologyStatusBits.FAULT_LATCH) == 0

    def test_topology_status_bits_calculation_faulted(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        engine.trip_fault(DiagnosticCode.CRC_S_FAULT)
        bits = engine.topology_status_bits
        assert (bits & CipSyncTopologyStatusBits.FAULT_LATCH) != 0
        assert (bits & CipSyncTopologyStatusBits.SAFETY_SYNC_ACTIVE) == 0

    def test_selected_monitored_node_write_and_sync(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        engine.selected_monitored_node = 2
        engine.sync_to_registers(rt)
        assert rt.read_word("%R2056") == 2

    def test_diagnostic_status_code_register_r2057_hex_values(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        codes = [
            (DiagnosticCode.CRC_S_FAULT, 0xEC01),
            (DiagnosticCode.EPI_WATCHDOG_TIMEOUT, 0xEC02),
            (DiagnosticCode.CLOCK_DRIFT_EXCEEDED, 0xEC03),
            (DiagnosticCode.TIMESTAMP_JITTER_FAULT, 0xEC04),
            (DiagnosticCode.GRANDMASTER_LOST, 0xEC05),
            (DiagnosticCode.SYNC_NODE_DISCONNECT, 0xEC06),
        ]
        for code, expected_hex in codes:
            engine.trip_fault(code)
            assert rt.read_uword("%R2057") == expected_hex

    def test_privilege_mode_system_enforced_in_sync(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)
        # Should not raise PrivilegeError during sync_to_registers
        engine.sync_to_registers(rt, privilege=PrivilegeMode.SYSTEM)
        assert rt.read_word("%R2050") == 1


# ============================================================================
# 9. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate Pure IEC 61131-3 Structured Text POU validation with STParser and SecurityGuard."""

    def test_pou_constant_defined_and_non_empty(self) -> None:
        assert isinstance(CIP_SAFETY_SYNC_BRIDGE_SYNC_POU, str)
        assert len(CIP_SAFETY_SYNC_BRIDGE_SYNC_POU.strip()) > 50
        assert CIP_SAFETY_SYNC_POU == CIP_SAFETY_SYNC_BRIDGE_SYNC_POU

    def test_pou_security_guard_assert_pure_st(self) -> None:
        # Should pass without raising LadderForbiddenError or other exceptions
        SecurityGuard.assert_pure_st_content(CIP_SAFETY_SYNC_BRIDGE_SYNC_POU)

    def test_pou_st_parser_validate_code_success(self) -> None:
        res = STParser.validate_code(CIP_SAFETY_SYNC_BRIDGE_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_pou_st_parser_parse_pou_type_program(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_SYNC_BRIDGE_SYNC_POU)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "CipSafetySyncBridgeSync"

    def test_pou_st_parser_bound_registers_complete(self) -> None:
        ast = STParser.parse_pou(CIP_SAFETY_SYNC_BRIDGE_SYNC_POU)
        expected_regs = [
            "%R2050", "%R2051", "%R2052", "%R2053",
            "%R2054", "%R2055", "%R2056", "%R2057",
            "%M478", "%M479",
        ]
        for r in expected_regs:
            assert r in ast.bound_registers

    def test_verify_cip_safety_sync_pure_st_function(self) -> None:
        assert verify_cip_safety_sync_pure_st() is True
        assert verify_cip_safety_sync_pure_st(CIP_SAFETY_SYNC_BRIDGE_SYNC_POU) is True

    def test_pou_custom_healthy_st_passes(self) -> None:
        custom_st = """PROGRAM CustomSyncTest
VAR
    R2050 AT %R2050 : INT;
    R2051 AT %R2051 : INT;
    R2052 AT %R2052 : INT;
    R2053 AT %R2053 : INT;
    R2054 AT %R2054 : INT;
    R2055 AT %R2055 : UINT;
    R2056 AT %R2056 : INT;
    R2057 AT %R2057 : UINT;
    M478 AT %M478 : BOOL;
    M479 AT %M479 : BOOL;
END_VAR
M478 := TRUE;
M479 := FALSE;
END_PROGRAM
"""
        assert verify_cip_safety_sync_pure_st(custom_st) is True

    def test_pou_program_structure_and_delimiters(self) -> None:
        lines = CIP_SAFETY_SYNC_BRIDGE_SYNC_POU.strip().splitlines()
        assert lines[0].startswith("PROGRAM CipSafetySyncBridgeSync")
        assert lines[-1].strip() == "END_PROGRAM"

    def test_pou_logic_control_flow(self) -> None:
        assert "IF SafetySyncFaultActive" in CIP_SAFETY_SYNC_BRIDGE_SYNC_POU
        assert "TimeSyncMasterStatus = 1" in CIP_SAFETY_SYNC_BRIDGE_SYNC_POU
        assert "SynchronizedNodesCount = 4" in CIP_SAFETY_SYNC_BRIDGE_SYNC_POU


# ============================================================================
# 10. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Validate strict rejection of 6+ ladder logic constructs with LadderForbiddenError."""

    def test_ladder_normally_open_contact_rejected(self) -> None:
        code = "PROGRAM L1\nVAR x: BOOL; END_VAR\n|---[ ]---|---( )---|\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_ladder_normally_closed_contact_rejected(self) -> None:
        code = "PROGRAM L2\nVAR x: BOOL; END_VAR\n|---[/]---|\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_ladder_output_coil_rejected(self) -> None:
        code = "PROGRAM L3\nVAR x: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_ladder_set_reset_coils_rejected(self) -> None:
        code_s = "PROGRAM L4\nVAR x: BOOL; END_VAR\n---(S)---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code_s)

        code_r = "PROGRAM L5\nVAR x: BOOL; END_VAR\n---(R)---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code_r)

    def test_ladder_rung_keyword_rejected(self) -> None:
        code = "PROGRAM L6\nVAR x: BOOL; END_VAR\nRUNG 1: XIC(Start) OTE(Motor);\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_ladder_network_keyword_rejected(self) -> None:
        code = "PROGRAM L7\nVAR x: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_ladder_xic_ote_mnemonics_rejected(self) -> None:
        code = "PROGRAM L8\nVAR x: BOOL; END_VAR\nXIC(Input1);\nOTE(Output1);\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_ladder_injected_inside_valid_st_rejected(self) -> None:
        corrupted = CIP_SAFETY_SYNC_BRIDGE_SYNC_POU + "\n---[ ]---\n"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(corrupted)

    def test_ladder_forbidden_error_properties(self) -> None:
        code = "|---[ ]---|"
        with pytest.raises(LadderForbiddenError) as exc_info:
            SecurityGuard.assert_pure_st_content(code)
        assert "Ladder" in str(exc_info.value) or "forbidden" in str(exc_info.value).lower()


# ============================================================================
# 11. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface compliance, scan_step, step, execute, reset, and 100-cycle soak."""

    def test_ilogicunit_interface_properties(self) -> None:
        engine = CipSafetySyncBridge()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "CipSafetySyncBridgeEngine"
        assert engine.priority == 1
        assert engine.is_enabled is True

    def test_scan_step_cycle_counter_and_clock_advance(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        start_ns = engine.current_time_ns
        assert engine.cycles_count == 0
        engine.scan_step(0.010)
        assert engine.cycles_count == 1
        assert engine.current_time_ns == start_ns + 10_000_000

    def test_step_convenience_wrapper(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        engine.step(0.010)
        assert engine.cycles_count == 1

    def test_execute_with_scan_context_variations(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)

        ctx1 = ScanContext(dt_s=0.010, register_table=rt)
        engine.execute(ctx1)
        assert engine.cycles_count == 1

        ctx2 = ScanContext(dt_ms=10.0, register_table=rt)
        engine.execute(ctx2)
        assert engine.cycles_count == 2

    def test_reset_restores_nominal_state(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        engine.trip_fault(DiagnosticCode.CRC_S_FAULT, node_index=1)
        assert engine.is_fault_active is True

        engine.reset()
        assert engine.is_fault_active is False
        assert engine.is_active is True
        assert engine.diagnostic_code == DiagnosticCode.SYNC_OK

    def test_send_sync_frame_transmission_counters(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        assert engine.packets_transmitted == 0
        pkt = engine.send_sync_frame(node_index=0, payload_word=0x0100)
        assert engine.packets_transmitted == 1
        assert pkt.source_node_index == 0
        assert pkt.verify_crcs() is True
        assert pkt.verify_dual_channel() is True

    def test_100_cycle_soak_stability(self) -> None:
        rt = RegisterTable()
        engine = CipSafetySyncBridge(register_table=rt, auto_activate=True)

        for cycle in range(1, 101):
            now_ns = engine.current_time_ns
            for nid in range(4):
                pkt = create_valid_sync_packet(node_index=nid, sequence_number=cycle, timestamp_ns=now_ns)
                engine.process_packet(pkt)
            engine.scan_step(0.010)

        assert engine.cycles_count == 100
        assert engine.is_active is True
        assert engine.is_fault_active is False
        assert engine.diagnostic_code == DiagnosticCode.SYNC_OK

    def test_100_cycle_soak_no_drift_or_nan(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        for _ in range(100):
            engine.scan_step(0.010)
        assert not math.isnan(engine.clock_drift_ppm)
        assert not math.isinf(engine.clock_drift_ppm)
        assert not math.isnan(engine.sync_jitter_max_ns)
        assert not math.isinf(engine.sync_jitter_max_ns)

    def test_100_cycle_heap_and_collection_stability(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        for _ in range(100):
            engine.scan_step(0.010)
        # Node list remains exactly 4
        assert len(engine.nodes) == 4
        assert engine.words_processed == 100

    def test_engine_packet_processing_counters(self) -> None:
        engine = CipSafetySyncBridge(auto_activate=True)
        assert engine.packets_processed == 0
        for i in range(4):
            pkt = create_valid_sync_packet(node_index=i)
            engine.process_packet(pkt)
        assert engine.packets_processed == 4
        assert engine.validator.packets_validated == 4


# ============================================================================
# 12. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate deterministic 9-stage runner export, evidence file, and strict 4-state contract."""

    def test_runner_returns_strict_4_state_dict(self) -> None:
        res = run_cip_safety_sync_verification()
        assert isinstance(res, dict)
        assert "status" in res
        assert "error_code" in res
        assert "details" in res
        assert "data" in res

    def test_runner_status_is_success(self) -> None:
        res = run_cip_safety_sync_verification()
        assert res["status"] == "success"

    def test_runner_error_code_is_none(self) -> None:
        res = run_cip_safety_sync_verification()
        assert res["error_code"] is None

    def test_runner_total_and_passed_stages_count(self) -> None:
        res = run_cip_safety_sync_verification()
        assert res["total_stages"] == 9
        assert res["stages_passed"] == 9
        assert res["passed_stages"] == 9

    def test_runner_stage_results_structure(self) -> None:
        res = run_cip_safety_sync_verification()
        stages = res["data"]["stages"]
        assert len(stages) == 9
        for s in stages:
            assert "stage" in s
            assert "name" in s
            assert "passed" in s
            assert s["passed"] is True
            assert "timing_ms" in s
            assert "details" in s

    def test_runner_data_dictionary_contents(self) -> None:
        res = run_cip_safety_sync_verification()
        data = res["data"]
        assert data["work_package"] == "W244"
        assert "IEEE 1588" in data["protocol"]
        assert data["classes"] == [0x39, 0x3A, 0x3B, 0x43]
        assert "%R2050" in data["register_map"]
        assert "%M478" in data["register_map"]

    def test_runner_custom_output_file_emission(self, tmp_path: Path) -> None:
        out_file = tmp_path / "custom_evidence.json"
        res = run_cip_safety_sync_verification(output_path=out_file)
        assert out_file.exists()
        loaded = json.loads(out_file.read_text(encoding="utf-8"))
        assert loaded["status"] == "success"
        assert loaded["total_stages"] == 9

    def test_runner_custom_work_package_label(self) -> None:
        res = run_cip_safety_sync_verification(work_package="W244_CUSTOM")
        assert res["data"]["work_package"] == "W244_CUSTOM"

    def test_verification_script_cli_execution(self) -> None:
        cmd = [sys.executable, "scripts/run_cip_safety_sync_verification.py"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        assert proc.returncode == 0
        assert "ALL 9 CIP Safety Time-Synchronized protocol stages PASSED" in proc.stdout or "Stages Passed: 9/9" in proc.stdout

    def test_strict_4_state_contract_keys_and_types(self) -> None:
        res = run_cip_safety_sync_verification()
        allowed_statuses = {"success", "failed", "blocked", "inconclusive"}
        assert res["status"] in allowed_statuses
        assert res["error_code"] is None or isinstance(res["error_code"], str)
        assert isinstance(res["details"], str)
        assert isinstance(res["data"], dict)
