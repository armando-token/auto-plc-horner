"""Comprehensive Unit and Integration Test Suite for Industrial CIP Sync IEEE 802.1AS gPTP Engine.

Work Package: W208 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Test Coverage (60+ Unit Tests across 11 Sections):
1. Section 1: Constants, Enums, and Configuration Defaults (GPTP_VERSION, GptpState, DiagnosticCode, ClockClass, etc.).
2. Section 2: Clock Identity & Quality (EUI-64 from MAC, hex, bytes, GptpClockQuality pack/unpack, ordering).
3. Section 3: BMCA Dataset Comparison, Priority Rankings, & Master Selection (all 7 IEEE 802.1AS criteria).
4. Section 4: Pdelay Framing & Peer-to-Peer Path Delay Math (Pdelay_Req, Pdelay_Resp, Pdelay_Resp_Follow_Up, p2p math).
5. Section 5: Master/Slave Timestamp Synthesis, Phase Offset, & Drift Compensation (two-step sync, PI servo).
6. Section 6: TSN 802.1Qbv Time-Aware Queue Gating & Schedule Slot Assignment (TAS GCL, Guard Band, CBS).
7. Section 7: Fault Trips (0xE001..0xE004) & Process Safety Interlocks (timeout, delay, jitter, GM lost, reset).
8. Section 8: Horner OCS Register Synchronization (%R1690..%R1697, %M394..%M395 with PrivilegeMode.SYSTEM).
9. Section 9: ILogicUnit Scan Step Integration & Watchdog Simulation (clock progression, timeouts, reset).
10. Section 10: Pure ST POU Validation & Anti-Ladder Rejection (SecurityGuard.assert_pure_st_content, STParser).
11. Section 11: 9-Stage Verification Runner & JSON Export (run_cip_sync_gptp_verification, CIP Time Sync Object).
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import tempfile
import time
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import HardwareLockoutError, LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext, ILogicUnit
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cip_sync_gptp import (
    CIP_SYNC_CLASS_ID,
    CIP_SYNC_GPTP_POU,
    CIP_SYNC_GPTP_SYNC_POU,
    CIPSyncGPTPEngine,
    CIPTimeSyncObject,
    ClockClass,
    DEFAULT_ANNOUNCE_INTERVAL_S,
    DEFAULT_ANNOUNCE_RECEIPT_TIMEOUT,
    DEFAULT_DOMAIN_NUMBER,
    DEFAULT_JITTER_SPIKE_THRESHOLD_NS,
    DEFAULT_JITTER_TARGET_NS,
    DEFAULT_PDELAY_INTERVAL_S,
    DEFAULT_STEP_THRESHOLD_NS,
    DEFAULT_SYNC_INTERVAL_S,
    DEFAULT_SYNC_RECEIPT_TIMEOUT_S,
    DEFAULT_SYNC_THRESHOLD_NS,
    DEFAULT_TSN_CYCLE_TIME_NS,
    DiagnosticCode,
    DiagnosticStatusCode,
    GPTP_TRANSPORT_SPECIFIC,
    GPTP_VERSION,
    MAX_ALLOWABLE_PATH_DELAY_NS,
    MAX_SERVO_DRIFT_PPB,
    NOMINAL_MEAN_PATH_DELAY_NS,
    AnnounceMessage,
    BMCA,
    BestMasterClockAlgorithm,
    CipSyncGptpClockClass,
    CipSyncGptpDiagnosticCode,
    CipSyncGptpEngine,
    CipSyncGptpState,
    CipTimeSyncObject,
    FollowUpMessage,
    GptpAnnounceMessage,
    GptpBMCA,
    GptpClockClass,
    GptpClockIdentity,
    GptpClockQuality,
    GptpDataset,
    GptpDiagnosticCode,
    GptpFlagField,
    GptpFollowUpMessage,
    GptpHeader,
    GptpMessageType,
    GptpPdelayReqMessage,
    GptpPdelayRespFollowUpMessage,
    GptpPdelayRespMessage,
    GptpPortIdentity,
    GptpServo,
    GptpState,
    GptpSyncMessage,
    GptpSyncState,
    GptpTimeInterval,
    GptpTimestamp,
    PdelayReqMessage,
    PdelayRespFollowUpMessage,
    PdelayRespMessage,
    PtpClockClass,
    PtpClockIdentity,
    PtpClockQuality,
    PtpDataset,
    PtpDiagnosticCode,
    PtpFlagField,
    PtpFollowUpMessage,
    PtpHeader,
    PtpMessageType,
    PtpPortIdentity,
    PtpPortState,
    PtpServo,
    PtpSyncMessage,
    PtpTimeInterval,
    PtpTimestamp,
    SyncEngineState,
    SyncMessage,
    TsnCreditBasedShaper,
    TsnGateControlEntry,
    TsnGateControlList,
    TsnTasSchedule,
    calculate_peer_path_delay,
    decode_dint_words,
    encode_dint_words,
    run_cip_sync_gptp_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
)


# ============================================================================
# Section 1: Constants, Enums, and Configuration Defaults
# ============================================================================

class TestGptpConstantsAndEnums:
    """Tests for protocol constants, timing parameters, and enumerations."""

    def test_constants_and_timing_defaults(self) -> None:
        assert GPTP_VERSION == 2
        assert GPTP_TRANSPORT_SPECIFIC == 0x1
        assert CIP_SYNC_CLASS_ID == 0x43
        assert DEFAULT_DOMAIN_NUMBER == 0
        assert DEFAULT_PDELAY_INTERVAL_S == 1.0
        assert DEFAULT_SYNC_INTERVAL_S == 0.125
        assert DEFAULT_ANNOUNCE_INTERVAL_S == 1.0
        assert DEFAULT_ANNOUNCE_RECEIPT_TIMEOUT == 3
        assert DEFAULT_SYNC_RECEIPT_TIMEOUT_S == 1.0
        assert DEFAULT_SYNC_THRESHOLD_NS == 1000
        assert DEFAULT_JITTER_TARGET_NS == 1000.0
        assert DEFAULT_JITTER_SPIKE_THRESHOLD_NS == 15_000
        assert MAX_ALLOWABLE_PATH_DELAY_NS == 50_000
        assert MAX_SERVO_DRIFT_PPB == 32_767
        assert DEFAULT_STEP_THRESHOLD_NS == 100_000
        assert NOMINAL_MEAN_PATH_DELAY_NS == 1450

    def test_gptp_state_enum_values_and_aliases(self) -> None:
        assert GptpState.UNINITIALIZED == 0
        assert GptpState.INITIALIZING == 1
        assert GptpState.LISTENING == 2
        assert GptpState.SLAVE_LOCKED == 3
        assert GptpState.MASTER_GRANDMASTER == 4
        assert GptpState.SYNC_TIMEOUT_FAULT == 5
        assert GptpState.PATH_DELAY_EXCEEDED_FAULT == 6
        assert GptpSyncState is GptpState
        assert CipSyncGptpState is GptpState
        assert SyncEngineState is GptpState

    def test_clock_class_enum_values_and_aliases(self) -> None:
        assert ClockClass.PRIMARY_REF == 6
        assert ClockClass.HOLDOVER == 7
        assert ClockClass.DEGRADED == 52
        assert ClockClass.DEFAULT == 248
        assert ClockClass.SLAVE_ONLY == 255
        assert GptpClockClass is ClockClass
        assert CipSyncGptpClockClass is ClockClass

    def test_gptp_message_type_enum(self) -> None:
        assert GptpMessageType.SYNC == 0x0
        assert GptpMessageType.PDELAY_REQ == 0x2
        assert GptpMessageType.PDELAY_RESP == 0x3
        assert GptpMessageType.FOLLOW_UP == 0x8
        assert GptpMessageType.PDELAY_RESP_FOLLOW_UP == 0xA
        assert GptpMessageType.ANNOUNCE == 0xB
        assert GptpMessageType.SIGNALING == 0xC
        assert GptpMessageType.MANAGEMENT == 0xD

    def test_diagnostic_code_enum_values_and_aliases(self) -> None:
        assert DiagnosticCode.OK == 0x0000
        assert DiagnosticCode.SYNC_TIMEOUT == 0xE001
        assert DiagnosticCode.PATH_DELAY_EXCEEDED == 0xE002
        assert DiagnosticCode.JITTER_DRIFT_EXCEEDED == 0xE003
        assert DiagnosticCode.GRANDMASTER_LOST == 0xE004
        assert GptpDiagnosticCode is DiagnosticCode
        assert CipSyncGptpDiagnosticCode is DiagnosticCode
        assert DiagnosticStatusCode is DiagnosticCode
        assert DiagnosticCode.ERR_SYNC_TIMEOUT == 0xE001
        assert DiagnosticCode.ERR_PATH_DELAY_EXCEEDED == 0xE002
        assert DiagnosticCode.ERR_JITTER_DRIFT_EXCEEDED == 0xE003
        assert DiagnosticCode.ERR_GRANDMASTER_LOST == 0xE004

    def test_gptp_flag_field_bits(self) -> None:
        assert GptpFlagField.TWO_STEP == 0x0002
        assert GptpFlagField.UNICAST == 0x0004
        assert GptpFlagField.PTP_TIMESCALE == 0x0008
        assert GptpFlagField.TIME_TRACEABLE == 0x0010
        assert GptpFlagField.FREQUENCY_TRACEABLE == 0x0020
        assert GptpFlagField.SYNCHRONIZATION_UNCERTAIN == 0x0040

    def test_time_interval_properties_and_arithmetic(self) -> None:
        interval = GptpTimeInterval(2_500_000_000)
        assert interval.seconds == 2
        assert interval.nanoseconds == 500_000_000
        assert interval.to_ns() == 2_500_000_000
        assert interval.to_float_seconds() == 2.5

    def test_timestamp_arithmetic_overflow_and_packing(self) -> None:
        ts = GptpTimestamp(seconds=10, nanoseconds=999_999_999)
        ts_next = ts + 1
        assert ts_next.seconds == 11
        assert ts_next.nanoseconds == 0
        assert ts_next.to_ns() == 11_000_000_000

        # Subtraction yields time interval
        diff = ts_next - ts
        assert isinstance(diff, GptpTimeInterval)
        assert diff.to_ns() == 1

        # Float seconds conversion
        ts_float = GptpTimestamp.from_float_seconds(12.3456789)
        assert ts_float.seconds == 12
        assert abs(ts_float.to_float_seconds() - 12.3456789) < 1e-6

        # Pack and unpack roundtrip (10 bytes)
        raw_packed = ts_next.pack()
        assert len(raw_packed) == 10
        unpacked = GptpTimestamp.unpack(raw_packed)
        assert unpacked == ts_next


# ============================================================================
# Section 2: Clock Identity & Quality
# ============================================================================

class TestGptpClockIdentityAndQuality:
    """Tests for EUI-64 clock identity synthesis, byte operations, and clock quality."""

    def test_clock_identity_eui64_mac_translation(self) -> None:
        mac = "00-11-22-33-44-55"
        cid = GptpClockIdentity.from_mac(mac)
        assert cid.to_hex() == "00-11-22-FF-FE-33-44-55"
        assert len(cid.to_bytes()) == 8

    def test_clock_identity_representations_and_defaults(self) -> None:
        cid_def = GptpClockIdentity.default_local()
        assert cid_def.to_hex() == "00-80-C2-FF-FE-01-20-80"
        assert isinstance(cid_def.to_int(), int)
        assert str(cid_def) == "00-80-C2-FF-FE-01-20-80"
        assert repr(cid_def) == "GptpClockIdentity('00-80-C2-FF-FE-01-20-80')"

    def test_clock_identity_comparisons_and_hashing(self) -> None:
        cid1 = GptpClockIdentity("00-00-00-00-00-00-00-01")
        cid2 = GptpClockIdentity("00-00-00-00-00-00-00-02")
        assert cid1 < cid2
        assert cid1 <= cid2
        assert cid2 > cid1
        assert cid2 >= cid1
        assert cid1 != cid2
        assert hash(cid1) != hash(cid2)

    def test_clock_quality_pack_unpack_roundtrip(self) -> None:
        cq = GptpClockQuality(clockClass=int(ClockClass.PRIMARY_REF), clockAccuracy=0x20, offsetScaledLogVariance=0x4000)
        packed = cq.pack()
        assert len(packed) == 4
        unpacked = GptpClockQuality.unpack(packed)
        assert unpacked.clockClass == 6
        assert unpacked.clockAccuracy == 0x20
        assert unpacked.offsetScaledLogVariance == 0x4000

    def test_clock_quality_lexicographical_ordering(self) -> None:
        cq_best = GptpClockQuality(clockClass=6, clockAccuracy=0x20, offsetScaledLogVariance=0x4000)
        cq_worse = GptpClockQuality(clockClass=7, clockAccuracy=0x21, offsetScaledLogVariance=0x5000)
        assert cq_best < cq_worse
        assert cq_best <= cq_worse
        assert cq_worse > cq_best


# ============================================================================
# Section 3: BMCA Dataset Comparison & Grandmaster Clock Selection
# ============================================================================

class TestBestMasterClockAlgorithm:
    """Tests for IEEE 802.1AS BMCA priority hierarchies and master election."""

    def test_bmca_priority1_superiority(self) -> None:
        ds_prio100 = GptpDataset(priority1=100, clockQuality=GptpClockQuality(clockClass=248))
        ds_prio128 = GptpDataset(priority1=128, clockQuality=GptpClockQuality(clockClass=6))
        # priority1=100 strictly wins over priority1=128 even if 128 has clockClass=6
        assert BMCA.compare_datasets(ds_prio100, ds_prio128) == -1
        assert BMCA.compare_datasets(ds_prio128, ds_prio100) == 1

    def test_bmca_clock_class_hierarchy(self) -> None:
        ds_prim = GptpDataset(clockQuality=GptpClockQuality(clockClass=int(ClockClass.PRIMARY_REF)))
        ds_hold = GptpDataset(clockQuality=GptpClockQuality(clockClass=int(ClockClass.HOLDOVER)))
        ds_degr = GptpDataset(clockQuality=GptpClockQuality(clockClass=int(ClockClass.DEGRADED)))
        ds_defl = GptpDataset(clockQuality=GptpClockQuality(clockClass=int(ClockClass.DEFAULT)))

        assert BMCA.compare_datasets(ds_prim, ds_hold) == -1
        assert BMCA.compare_datasets(ds_hold, ds_degr) == -1
        assert BMCA.compare_datasets(ds_degr, ds_defl) == -1

    def test_bmca_clock_accuracy_and_variance_tiebreaking(self) -> None:
        ds_acc1 = GptpDataset(clockQuality=GptpClockQuality(clockClass=248, clockAccuracy=0x20, offsetScaledLogVariance=0x5000))
        ds_acc2 = GptpDataset(clockQuality=GptpClockQuality(clockClass=248, clockAccuracy=0x21, offsetScaledLogVariance=0x5000))
        assert BMCA.compare_datasets(ds_acc1, ds_acc2) == -1

        ds_var1 = GptpDataset(clockQuality=GptpClockQuality(clockClass=248, clockAccuracy=0x20, offsetScaledLogVariance=0x3000))
        ds_var2 = GptpDataset(clockQuality=GptpClockQuality(clockClass=248, clockAccuracy=0x20, offsetScaledLogVariance=0x4000))
        assert BMCA.compare_datasets(ds_var1, ds_var2) == -1

    def test_bmca_priority2_tiebreaking(self) -> None:
        ds_p2_a = GptpDataset(priority2=10)
        ds_p2_b = GptpDataset(priority2=20)
        assert BMCA.compare_datasets(ds_p2_a, ds_p2_b) == -1

    def test_bmca_clock_identity_tiebreaking(self) -> None:
        cid_low = GptpClockIdentity("00-00-00-00-00-00-00-01")
        cid_high = GptpClockIdentity("00-00-00-00-00-00-00-02")
        ds_id1 = GptpDataset(clockIdentity=cid_low)
        ds_id2 = GptpDataset(clockIdentity=cid_high)
        assert BMCA.compare_datasets(ds_id1, ds_id2) == -1

    def test_bmca_steps_removed_ranking(self) -> None:
        ds_step0 = GptpDataset(stepsRemoved=0)
        ds_step2 = GptpDataset(stepsRemoved=2)
        assert BMCA.compare_datasets(ds_step0, ds_step2) == -1

    def test_bmca_select_master_local_win_and_slave_tracking(self) -> None:
        local_gm = GptpDataset(clockQuality=GptpClockQuality(clockClass=int(ClockClass.PRIMARY_REF)))
        foreign_node = GptpDataset(clockQuality=GptpClockQuality(clockClass=int(ClockClass.DEFAULT)))

        # Local node is superior -> Local becomes Master
        best, is_local = BMCA.select_master(local_gm, [foreign_node])
        assert is_local is True
        assert best == local_gm

        # Foreign node is superior -> Local tracks as Slave
        best, is_local = BMCA.select_master(foreign_node, [local_gm])
        assert is_local is False
        assert best == local_gm


# ============================================================================
# Section 4: Pdelay Framing & Peer-to-Peer Path Delay Math
# ============================================================================

class TestPdelayFramingAndPathDelayMath:
    """Tests for IEEE 802.1AS Pdelay message serialization and propagation math."""

    def test_gptp_header_pack_unpack_34_bytes(self) -> None:
        cid = GptpClockIdentity("00-80-C2-FF-FE-01-20-80")
        hdr = GptpHeader.create(
            msg_type=GptpMessageType.PDELAY_REQ,
            source_identity=cid,
            sequence_id=42,
            two_step=True,
            msg_len=54,
        )
        packed = hdr.pack()
        assert len(packed) == 34
        unpacked = GptpHeader.unpack(packed)
        assert unpacked.messageType == int(GptpMessageType.PDELAY_REQ)
        assert unpacked.sequenceId == 42
        assert unpacked.sourcePortIdentity.clockIdentity == cid

    def test_pdelay_req_message_structure(self) -> None:
        cid = GptpClockIdentity("00-80-C2-FF-FE-01-20-80")
        hdr = GptpHeader.create(GptpMessageType.PDELAY_REQ, cid, sequence_id=1, msg_len=54)
        t1 = GptpTimestamp(seconds=1000, nanoseconds=50_000)
        req = GptpPdelayReqMessage(header=hdr, originTimestamp=t1)
        assert req.header.messageType == int(GptpMessageType.PDELAY_REQ)
        assert req.originTimestamp == t1

    def test_pdelay_resp_and_follow_up_structure(self) -> None:
        cid = GptpClockIdentity("00-80-C2-FF-FE-01-20-80")
        hdr_resp = GptpHeader.create(GptpMessageType.PDELAY_RESP, cid, sequence_id=1, msg_len=54)
        t2 = GptpTimestamp(seconds=1000, nanoseconds=51_450)
        resp = GptpPdelayRespMessage(header=hdr_resp, requestReceiptTimestamp=t2)
        assert resp.requestReceiptTimestamp == t2

        hdr_fu = GptpHeader.create(GptpMessageType.PDELAY_RESP_FOLLOW_UP, cid, sequence_id=1, msg_len=54)
        t3 = GptpTimestamp(seconds=1000, nanoseconds=71_450)
        resp_fu = GptpPdelayRespFollowUpMessage(header=hdr_fu, responseOriginTimestamp=t3)
        assert resp_fu.responseOriginTimestamp == t3

    def test_calculate_peer_path_delay_canonical_equation(self) -> None:
        t1 = GptpTimestamp(1000, 100_000)
        t2 = GptpTimestamp(1000, 101_450)  # +1450 ns
        t3 = GptpTimestamp(1000, 121_450)  # +20,000 ns turnaround
        t4 = GptpTimestamp(1000, 122_900)  # +1450 ns

        # round_trip = 122_900 - 100_000 = 22,900 ns
        # turnaround = 121_450 - 101_450 = 20,000 ns
        # mean_path_delay = (22_900 - 20_000) // 2 = 1450 ns
        pdelay = calculate_peer_path_delay(t1, t2, t3, t4)
        assert pdelay == 1450

    def test_calculate_peer_path_delay_with_rate_ratio(self) -> None:
        t1 = 100_000
        t2 = 101_450
        t3 = 121_450
        t4 = 122_900
        # Rate ratio 1.0001 (100 ppm neighbor drift)
        pdelay = calculate_peer_path_delay(t1, t2, t3, t4, neighbor_rate_ratio=1.0001)
        assert abs(pdelay - 1449) <= 1

    def test_full_pdelay_handshake_flow_in_engine(self) -> None:
        engine = CipSyncGptpEngine()
        t1 = GptpTimestamp(1000, 100_000)
        t2 = GptpTimestamp(1000, 101_450)
        t3 = GptpTimestamp(1000, 121_450)
        t4 = GptpTimestamp(1000, 122_900)

        res = engine.measure_pdelay(t1, t2, t3, t4)
        assert res["mean_path_delay_ns"] == 1450
        assert res["turnaround_ns"] == 20_000
        assert res["round_trip_ns"] == 22_900
        assert engine.mean_path_delay_ns == 1450


# ============================================================================
# Section 5: Master/Slave Timestamp Synthesis, Phase Offset, & Drift Compensation
# ============================================================================

class TestMasterSlaveSyncAndServo:
    """Tests for two-step Sync + Follow_Up processing, phase calculation, and PI servo."""

    def test_sync_and_follow_up_framing(self) -> None:
        cid = GptpClockIdentity.default_local()
        hdr_sync = GptpHeader.create(GptpMessageType.SYNC, cid, sequence_id=10, two_step=True)
        sync_msg = GptpSyncMessage(header=hdr_sync)
        assert sync_msg.header.messageType == int(GptpMessageType.SYNC)

        hdr_fu = GptpHeader.create(GptpMessageType.FOLLOW_UP, cid, sequence_id=10, two_step=True)
        t1 = GptpTimestamp(seconds=2000, nanoseconds=300_000)
        fu_msg = GptpFollowUpMessage(header=hdr_fu, preciseOriginTimestamp=t1)
        assert fu_msg.preciseOriginTimestamp == t1

    def test_two_step_sync_offset_computation(self) -> None:
        engine = CipSyncGptpEngine()
        engine.mean_path_delay_ns = 1450

        t1 = GptpTimestamp(seconds=2000, nanoseconds=500_000)
        t2 = GptpTimestamp(seconds=2000, nanoseconds=501_200)

        cid = GptpClockIdentity("00-80-C2-FF-FE-01-00-01")
        sync_msg = GptpSyncMessage(header=GptpHeader.create(GptpMessageType.SYNC, cid, sequence_id=5, two_step=True))
        engine.process_sync(sync_msg, ingress_timestamp=t2)

        fu_msg = GptpFollowUpMessage(
            header=GptpHeader.create(GptpMessageType.FOLLOW_UP, cid, sequence_id=5, two_step=True),
            preciseOriginTimestamp=t1,
        )
        ok = engine.process_follow_up(fu_msg)
        assert ok is True
        # offset = (t2 - t1) - mean_path_delay = 1200 - 1450 = -250 ns
        assert engine.offset_from_master_ns == -250

    def test_sequence_id_mismatch_rejection(self) -> None:
        engine = CipSyncGptpEngine()
        cid = GptpClockIdentity.default_local()
        sync_msg = GptpSyncMessage(header=GptpHeader.create(GptpMessageType.SYNC, cid, sequence_id=5))
        engine.process_sync(sync_msg)

        fu_msg_wrong = GptpFollowUpMessage(header=GptpHeader.create(GptpMessageType.FOLLOW_UP, cid, sequence_id=6))
        assert engine.process_follow_up(fu_msg_wrong) is False

    def test_pi_clock_servo_convergence_and_locking(self) -> None:
        servo = GptpServo(kp=0.6, ki=1.0)
        sim_offset = -600
        drift_ppb = 120

        for _ in range(40):
            drift, adj = servo.sample(sim_offset, dt=0.125)
            net_drift = int(round((drift_ppb - drift) * 1e-9 * 0.125 * 1e9))
            sim_offset = int(sim_offset - adj + net_drift)

        assert abs(sim_offset) < 50
        assert servo.is_locked is True
        assert servo.current_jitter_ns < 1000.0

    def test_pi_clock_servo_jitter_clamping(self) -> None:
        servo = GptpServo(kp=0.5, ki=0.1)
        servo.sample(100, dt=0.125)
        # Inject large 30,000 ns jitter spike
        drift, adj = servo.sample(30_000, dt=0.125)
        assert servo.jitter_spike_count == 1
        # Phase adjustment is clamped to jitter_spike_threshold (15,000 * 0.5 = 7500)
        assert adj <= 7500

    def test_pi_clock_servo_coarse_step_threshold(self) -> None:
        servo = GptpServo()
        # Offset > 100,000 ns triggers coarse step
        drift, adj = servo.sample(150_000, dt=0.125)
        assert adj == 150_000
        assert servo.is_locked is False


# ============================================================================
# Section 6: TSN 802.1Qbv Time-Aware Queue Gating & Schedule Slot Assignment
# ============================================================================

class TestTsn8021QbvTimeAwareQueueGating:
    """Tests for TSN 802.1Qbv TAS Gate Control List and 802.1Qav Credit-Based Shaper."""

    def test_tsn_gate_control_entry_traffic_classes(self) -> None:
        # TC7 and TC6 open (0xC0), others closed
        entry = TsnGateControlEntry(slot_index=0, gate_states=0xC0, time_interval_ns=200_000, name="Critical")
        assert entry.is_tc_open(7) is True
        assert entry.is_tc_open(6) is True
        assert entry.is_tc_open(5) is False
        assert entry.is_tc_open(0) is False

    def test_tsn_tas_schedule_creation_and_cycle_time(self) -> None:
        tas = TsnTasSchedule.create_default(base_time=GptpTimestamp(0, 0))
        assert tas.cycle_time_ns == 1_000_000  # 1 ms total cycle
        assert len(tas.entries) == 2

    def test_tsn_tas_slot_assignment_by_timestamp(self) -> None:
        tas = TsnTasSchedule.create_default(base_time=GptpTimestamp(0, 0))
        # 50 us into cycle -> slot 0 (0xC0)
        ts_crit = GptpTimestamp(0, 50_000)
        assert tas.get_current_gate_state(ts_crit) == 0xC0
        assert tas.is_traffic_class_open(ts_crit, 7) is True
        assert tas.is_traffic_class_open(ts_crit, 0) is False

        # 500 us into cycle -> slot 1 (0x3F)
        ts_be = GptpTimestamp(0, 500_000)
        assert tas.get_current_gate_state(ts_be) == 0x3F
        assert tas.is_traffic_class_open(ts_be, 7) is False
        assert tas.is_traffic_class_open(ts_be, 0) is True

    def test_tsn_guard_band_calculation(self) -> None:
        tas = TsnTasSchedule.create_default()
        # 1000 Mbps, 1518 bytes frame -> 1518 * 8 / 1000 * 1000 = 12144 ns
        gb = tas.calculate_guard_band(link_speed_mbps=1000, max_frame_bytes=1518)
        assert gb == 12144

    def test_tsn_credit_based_shaper_cbs_transmission(self) -> None:
        cbs = TsnCreditBasedShaper(idle_slope_kbps=100_000, send_slope_kbps=-900_000, hi_credit=2000, lo_credit=-2000)
        assert cbs.can_transmit() is True

        # Transmitting for 10 us -> credit decreases
        cbs.update(dt_s=0.00001, transmitting=True)
        assert cbs.current_credit < 0.0

    def test_tsn_credit_based_shaper_cbs_idle_accumulation(self) -> None:
        cbs = TsnCreditBasedShaper(idle_slope_kbps=100_000, send_slope_kbps=-900_000, hi_credit=2000, lo_credit=-2000)
        cbs.current_credit = -500.0
        # Idle for 0.01 s -> accumulates credit
        cbs.update(dt_s=0.01, transmitting=False)
        assert cbs.current_credit > 0.0
        assert cbs.current_credit <= 2000.0


# ============================================================================
# Section 7: Fault Trips (0xE001..0xE004) & Process Safety Interlocks
# ============================================================================

class TestFaultTripsAndSafetyInterlocks:
    """Tests for 0xE001..0xE004 diagnostic fault trips and operator reset."""

    def test_fault_sync_timeout_0xE001(self) -> None:
        rt = RegisterTable()
        engine = CipSyncGptpEngine(reg_table=rt)
        engine.state = GptpSyncState.SLAVE_LOCKED
        engine.is_synchronized = True

        engine.simulate_sync_timeout()
        assert engine.diagnostic_code == DiagnosticCode.SYNC_TIMEOUT
        assert engine.state == GptpSyncState.SYNC_TIMEOUT_FAULT
        assert engine.is_synchronized is False
        assert engine.fault_trip is True
        assert rt.read_word("%R1690") == 5
        assert rt.read_uword("%R1697") == 0xE001
        assert rt.read_bit("%M394") is False
        assert rt.read_bit("%M395") is True

    def test_fault_path_delay_exceeded_0xE002(self) -> None:
        rt = RegisterTable()
        engine = CipSyncGptpEngine(reg_table=rt)
        engine.simulate_path_delay_exceeded(65_000)
        assert engine.diagnostic_code == DiagnosticCode.PATH_DELAY_EXCEEDED
        assert engine.state == GptpSyncState.PATH_DELAY_EXCEEDED_FAULT
        assert engine.is_synchronized is False
        assert engine.fault_trip is True
        assert rt.read_word("%R1690") == 6
        assert rt.read_uword("%R1697") == 0xE002
        assert rt.read_bit("%M394") is False
        assert rt.read_bit("%M395") is True

    def test_fault_jitter_drift_exceeded_0xE003(self) -> None:
        rt = RegisterTable()
        engine = CipSyncGptpEngine(reg_table=rt)
        engine.simulate_jitter_drift_exceeded(20_000)
        assert engine.diagnostic_code == DiagnosticCode.JITTER_DRIFT_EXCEEDED
        assert engine.is_synchronized is False
        assert engine.fault_trip is True
        assert rt.read_uword("%R1697") == 0xE003
        assert rt.read_bit("%M394") is False
        assert rt.read_bit("%M395") is True

    def test_fault_grandmaster_lost_0xE004(self) -> None:
        rt = RegisterTable()
        engine = CipSyncGptpEngine(reg_table=rt)
        engine.simulate_grandmaster_lost()
        assert engine.diagnostic_code == DiagnosticCode.GRANDMASTER_LOST
        assert engine.state == GptpSyncState.LISTENING
        assert engine.is_synchronized is False
        assert engine.fault_trip is True
        assert rt.read_uword("%R1697") == 0xE004
        assert rt.read_bit("%M394") is False
        assert rt.read_bit("%M395") is True

    def test_fault_reset_handshake_restores_clean_state(self) -> None:
        rt = RegisterTable()
        engine = CipSyncGptpEngine(reg_table=rt)
        engine.simulate_sync_timeout()

        res = engine.reset_fault(force=True)
        assert res.status == AgentStatus.SUCCESS
        assert engine.diagnostic_code == DiagnosticCode.OK
        assert engine.state == GptpSyncState.LISTENING
        assert engine.fault_trip is False
        assert rt.read_uword("%R1697") == 0x0000
        assert rt.read_bit("%M395") is False

    def test_health_score_zeroes_during_fault(self) -> None:
        engine = CipSyncGptpEngine()
        engine.simulate_sync_timeout()
        score = engine._update_health_score()
        assert score == 0


# ============================================================================
# Section 8: Horner OCS Register Synchronization (%R1690..%R1697, %M394..%M395)
# ============================================================================

class TestHornerOcsRegisterMapping:
    """Tests for %R1690..%R1697 and %M394..%M395 register mapping with PrivilegeMode.SYSTEM."""

    def test_register_writes_require_system_privilege(self) -> None:
        rt = RegisterTable()
        safe_write_word(rt, "%R1690", 3)
        assert rt.read_word("%R1690") == 3

        safe_write_bit(rt, "%M394", True)
        assert rt.read_bit("%M394") is True

    def test_dint_word_encoding_decoding(self) -> None:
        low, high = encode_dint_words(371661)
        decoded = decode_dint_words(low, high)
        assert decoded == 371661

    def test_full_register_map_slave_locked(self) -> None:
        rt = RegisterTable()
        engine = CipSyncGptpEngine(reg_table=rt, clock_class=ClockClass.PRIMARY_REF)
        engine.state = GptpSyncState.SLAVE_LOCKED
        engine.local_clock = GptpTimestamp(seconds=123456, nanoseconds=500)
        engine.offset_from_master_ns = -250
        engine.mean_path_delay_ns = 1450
        engine.diagnostic_code = DiagnosticCode.OK
        engine.health_score = 95
        engine.is_synchronized = True
        engine.fault_trip = False
        engine.sync_to_registers(rt, PrivilegeMode.SYSTEM)

        assert rt.read_word("%R1690") == 3
        sec_decoded = decode_dint_words(rt.read_word("%R1691"), rt.read_word("%R1692"))
        assert sec_decoded == 123456
        assert rt.read_word("%R1693") == -250
        assert rt.read_word("%R1694") == 1450
        assert rt.read_word("%R1695") == 6
        assert rt.read_word("%R1696") == 95
        assert rt.read_uword("%R1697") == 0x0000
        assert rt.read_bit("%M394") is True
        assert rt.read_bit("%M395") is False

    def test_register_map_master_grandmaster_mode(self) -> None:
        rt = RegisterTable()
        engine = CipSyncGptpEngine(reg_table=rt, clock_class=ClockClass.PRIMARY_REF)
        engine.state = GptpSyncState.MASTER_GRANDMASTER
        engine.is_grandmaster = True
        engine.is_synchronized = True
        engine.fault_trip = False
        engine.sync_to_registers(rt, PrivilegeMode.SYSTEM)

        assert rt.read_word("%R1690") == 4
        assert rt.read_bit("%M394") is True
        assert rt.read_bit("%M395") is False

    def test_register_clamping_for_int16(self) -> None:
        rt = RegisterTable()
        engine = CipSyncGptpEngine(reg_table=rt)
        engine.offset_from_master_ns = 50_000  # Exceeds INT16 32767
        engine.sync_to_registers(rt, PrivilegeMode.SYSTEM)
        assert rt.read_word("%R1693") == 32767


# ============================================================================
# Section 9: ILogicUnit Scan Step Integration & Watchdog Simulation
# ============================================================================

class TestILogicUnitSimulation:
    """Tests for scan cycle stepping, clock advance, and timeout evaluation."""

    def test_ilogic_unit_interface_properties(self) -> None:
        engine = CipSyncGptpEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "cip_sync_gptp"
        assert engine.priority == 93
        assert engine.is_enabled is True

    def test_scan_step_clock_progression(self) -> None:
        engine = CipSyncGptpEngine()
        t_init = engine.local_clock.to_ns()
        engine.scan_step(dt=0.01)  # 10 ms
        t_after = engine.local_clock.to_ns()
        assert t_after - t_init == 10_000_000  # Exactly 10 ms advanced

    def test_scan_context_execution(self) -> None:
        rt = RegisterTable()
        engine = CipSyncGptpEngine(reg_table=rt)
        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=rt.read_register,
            set_register=lambda a, v: rt.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda k, d=None: d,
            set_variable=lambda k, v: None,
            record_fault=lambda f: None,
        )
        for _ in range(10):
            engine.execute(ctx)
        assert engine.total_scan_cycles == 10

    def test_watchdog_sync_timeout_in_slave_mode(self) -> None:
        engine = CipSyncGptpEngine()
        engine.state = GptpSyncState.SLAVE_LOCKED
        engine.sync_timeout_s = 0.5

        # Step 0.6 seconds without sync -> triggers 0xE001
        engine.scan_step(dt=0.6)
        assert engine.diagnostic_code == DiagnosticCode.SYNC_TIMEOUT
        assert engine.state == GptpSyncState.SYNC_TIMEOUT_FAULT

    def test_watchdog_announce_timeout_in_slave_mode(self) -> None:
        engine = CipSyncGptpEngine()
        engine.state = GptpSyncState.SLAVE_LOCKED
        engine.sync_timeout_s = 100.0  # Keep sync alive
        engine.announce_timeout_s = 2.0

        # Step 2.5 seconds without announce -> triggers 0xE004
        engine.scan_step(dt=2.5)
        assert engine.diagnostic_code == DiagnosticCode.GRANDMASTER_LOST
        assert engine.state == GptpSyncState.LISTENING


# ============================================================================
# Section 10: Pure ST POU Validation & Anti-Ladder Rejection
# ============================================================================

class TestPureStPouAndSecurityGuard:
    """Tests for IEC 61131-3 Pure Structured Text POU validation and anti-ladder guard."""

    def test_pure_st_pou_syntax_validation(self) -> None:
        res = STParser.validate_code(CIP_SYNC_GPTP_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_pure_st_pou_ast_registers_binding(self) -> None:
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(CIP_SYNC_GPTP_SYNC_POU)
        assert ast.name == "CipSyncGptpSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1690", "%R1691", "%R1692", "%R1693",
            "%R1694", "%R1695", "%R1696", "%R1697",
            "%M394", "%M395",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_pure_st_security_guard_clean(self) -> None:
        SecurityGuard.assert_pure_st_content(CIP_SYNC_GPTP_SYNC_POU)
        assert CIP_SYNC_GPTP_POU == CIP_SYNC_GPTP_SYNC_POU

    def test_anti_ladder_contacts_rejection(self) -> None:
        bad_contacts = [
            "PROGRAM Bad\nVAR X : BOOL;\nEND_VAR\n---[ ]---\nEND_PROGRAM",
            "PROGRAM Bad\nVAR X : BOOL;\nEND_VAR\n---[/]---\nEND_PROGRAM",
        ]
        for bad in bad_contacts:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad)

    def test_anti_ladder_coils_and_mnemonics_rejection(self) -> None:
        bad_ladder = [
            "PROGRAM Bad\nVAR X : BOOL;\nEND_VAR\n---( )---\nEND_PROGRAM",
            "PROGRAM Bad\nVAR X : BOOL;\nEND_VAR\n---(S)---\nEND_PROGRAM",
            "PROGRAM Bad\nVAR X : BOOL;\nEND_VAR\n---(R)---\nEND_PROGRAM",
            "PROGRAM Bad\nVAR X : BOOL;\nEND_VAR\nRUNG 1\nEND_PROGRAM",
            "PROGRAM Bad\nVAR X : BOOL;\nEND_VAR\nNETWORK 1\nEND_PROGRAM",
            "PROGRAM Bad\nVAR X : BOOL;\nEND_VAR\nXIC Coil_1\nEND_PROGRAM",
            "PROGRAM Bad\nVAR X : BOOL;\nEND_VAR\nOTE Coil_1\nEND_PROGRAM",
        ]
        for bad in bad_ladder:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad)


# ============================================================================
# Section 11: 9-Stage Verification Runner & JSON Export
# ============================================================================

class TestVerificationRunnerAndCipObject:
    """Tests for 9-stage verification suite execution, evidence emission, and CIP Object."""

    def test_verification_runner_returns_strict_4_state_success(self) -> None:
        res = run_cip_sync_gptp_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["stages_passed"] == 9
        assert res["total_stages"] == 9

    def test_verification_runner_all_9_stages_pass(self) -> None:
        res = run_cip_sync_gptp_verification()
        stages = res["data"]["stages"]
        assert len(stages) == 9
        for stage in stages:
            assert stage["passed"] is True
            assert len(stage["details"]) > 0

    def test_verification_runner_exports_valid_json(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            temp_path = tf.name

        try:
            res = run_cip_sync_gptp_verification(output_path=temp_path)
            assert Path(temp_path).exists()
            with open(temp_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["data"]["work_package"] == "W208"
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_cip_time_sync_object_attributes(self) -> None:
        engine = CipSyncGptpEngine()
        engine.state = GptpSyncState.SLAVE_LOCKED
        engine.is_synchronized = True
        engine.offset_from_master_ns = -250
        engine.mean_path_delay_ns = 1450

        cip_obj = engine.get_cip_object()
        assert isinstance(cip_obj, CipTimeSyncObject)
        assert cip_obj.IsSynchronized is True
        assert cip_obj.ClockState == int(GptpSyncState.SLAVE_LOCKED)
        assert cip_obj.OffsetFromMasterNs == -250
        assert cip_obj.MeanPathDelayNs == 1450
        assert cip_obj.DomainNumber == 0
