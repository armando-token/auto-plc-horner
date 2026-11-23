"""Comprehensive Unit and Integration Test Suite for Industrial EtherNet/IP CIP Sync & IEEE 1588 PTP Engine.

Work Package: W187 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Test Coverage (50+ Unit Tests across 11 Sections):
1. Section 1: Enums & Timestamps (PtpPortState, PtpClockClass, PtpMessageType, PtpDiagnosticCode, PtpTimestamp).
2. Section 2: Clock Identity & Quality (EUI-64 from MAC, hex, bytes, PtpClockQuality serialization & comparisons).
3. Section 3: Best Master Clock Algorithm (BMCA dataset comparisons across all 7 IEEE 1588 criteria).
4. Section 4: PTP Wire Message Framing (Header, Sync, Follow_Up, Delay_Req, Delay_Resp, Announce).
5. Section 5: Two-Step Timestamping & Path Delay (Canonical equations: ((t2-t1)+(t4-t3))//2 and (t2-t1)-mean_delay).
6. Section 6: PI Clock Servo Controller (Slewing, coarse stepping, drift adjustment in ppb, and jitter spike clamping).
7. Section 7: Pure IEC 61131-3 ST POU & SecurityGuard (STParser AST binding, anti-ladder construct rejection).
8. Section 8: Horner OCS Register Table Synchronization (%R1480..%R1487, %M345..%M346 with PrivilegeMode.SYSTEM).
9. Section 9: ILogicUnit 100-Cycle Simulation (scan_step, clock progression, drift steering, reset).
10. Section 10: Fault Scenarios & Process Safety Interlocks (0xD101..0xD104 trips, operator reset handshake).
11. Section 11: Deterministic 9-Stage Verification Runner (run_cip_sync_ptp_verification returns status == 'success').
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
from jev_cscape.telemetry.cip_sync_ptp import (
    CIP_SYNC_PTP_SYNC_POU,
    DEFAULT_ANNOUNCE_INTERVAL_S,
    DEFAULT_ANNOUNCE_RECEIPT_TIMEOUT,
    DEFAULT_JITTER_SPIKE_THRESHOLD_NS,
    DEFAULT_STEP_THRESHOLD_NS,
    DEFAULT_SYNC_INTERVAL_S,
    DEFAULT_SYNC_RECEIPT_TIMEOUT_S,
    DEFAULT_SYNC_THRESHOLD_NS,
    MAX_ALLOWABLE_JITTER_NS,
    MAX_SERVO_DRIFT_PPB,
    NOMINAL_MEAN_PATH_DELAY_NS,
    PTP_VERSION,
    BMCA,
    BestMasterClockAlgorithm,
    CIPSyncDiagnosticCode,
    CIPSyncPtpEngine,
    CipSyncDiagnosticCode,
    CipSyncPtpEngine,
    CipTimeSyncObject,
    PtpAnnounceMessage,
    PtpClockClass,
    PtpClockIdentity,
    PtpClockQuality,
    PtpClockState,
    PtpDataset,
    PtpDelayReqMessage,
    PtpDelayRespMessage,
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
    decode_dint_words,
    encode_dint_words,
    run_cip_sync_ptp_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
)


# ============================================================================
# Section 1: PTP Enums & Timestamp Conversions
# ============================================================================

class TestPtpEnumsAndTimestamps:
    """Tests for protocol enumeration types, bit flags, and timestamp arithmetic."""

    def test_ptp_port_state_enum_values_and_aliases(self) -> None:
        assert PtpPortState.DISABLED == 0
        assert PtpPortState.LISTENING == 1
        assert PtpPortState.PRE_MASTER == 2
        assert PtpPortState.MASTER == 3
        assert PtpPortState.PASSIVE == 4
        assert PtpPortState.UNCALIBRATED == 5
        assert PtpPortState.SLAVE == 6
        assert PtpPortState.FAULTY == 7
        assert PtpClockState is PtpPortState
        assert PtpPortState.Disabled == 0
        assert PtpPortState.Master == 3
        assert PtpPortState.Slave == 6

    def test_ptp_clock_class_enum_values(self) -> None:
        assert PtpClockClass.PRIMARY_REF == 6
        assert PtpClockClass.APPLICATION_SPECIFIC == 13
        assert PtpClockClass.DEFAULT == 248
        assert PtpClockClass.SLAVE_ONLY == 255

    def test_ptp_message_type_enum_values(self) -> None:
        assert PtpMessageType.SYNC == 0x0
        assert PtpMessageType.DELAY_REQ == 0x1
        assert PtpMessageType.PDELAY_REQ == 0x2
        assert PtpMessageType.PDELAY_RESP == 0x3
        assert PtpMessageType.FOLLOW_UP == 0x8
        assert PtpMessageType.DELAY_RESP == 0x9
        assert PtpMessageType.PDELAY_RESP_FOLLOW_UP == 0xA
        assert PtpMessageType.ANNOUNCE == 0xB
        assert PtpMessageType.SIGNALING == 0xC
        assert PtpMessageType.MANAGEMENT == 0xD

    def test_ptp_diagnostic_code_enum_values_and_aliases(self) -> None:
        assert PtpDiagnosticCode.OK == 0x0000
        assert PtpDiagnosticCode.BMCA_LOST_GM == 0xD101
        assert PtpDiagnosticCode.SYNC_TIMEOUT == 0xD102
        assert PtpDiagnosticCode.JITTER_SPIKE == 0xD103
        assert PtpDiagnosticCode.HARDWARE_LOCKOUT == 0xD104

        assert CipSyncDiagnosticCode is PtpDiagnosticCode
        assert CIPSyncDiagnosticCode is PtpDiagnosticCode
        assert PtpDiagnosticCode.ERR_BMCA_LOST_GM == 0xD101
        assert PtpDiagnosticCode.ERR_SYNC_TIMEOUT == 0xD102
        assert PtpDiagnosticCode.ERR_JITTER_SPIKE == 0xD103
        assert PtpDiagnosticCode.ERR_HARDWARE_LOCKOUT == 0xD104

    def test_ptp_flag_field_bitmasks(self) -> None:
        assert PtpFlagField.TWO_STEP == 0x0002
        assert PtpFlagField.UNICAST == 0x0004
        assert PtpFlagField.PTP_TIMESCALE == 0x0800
        flags = PtpFlagField.TWO_STEP | PtpFlagField.PTP_TIMESCALE
        assert bool(flags & PtpFlagField.TWO_STEP) is True
        assert bool(flags & PtpFlagField.UNICAST) is False

    def test_ptp_timestamp_construction_and_normalization(self) -> None:
        ts = PtpTimestamp(seconds=5, nanoseconds=500)
        assert ts.seconds == 5
        assert ts.nanoseconds == 500

        # Normalization of overflow nanoseconds
        ts_overflow = PtpTimestamp(seconds=10, nanoseconds=1_500_000_000)
        assert ts_overflow.seconds == 11
        assert ts_overflow.nanoseconds == 500_000_000

        # Normalization of negative nanoseconds
        ts_underflow = PtpTimestamp(seconds=10, nanoseconds=-200_000_000)
        assert ts_underflow.seconds == 9
        assert ts_underflow.nanoseconds == 800_000_000

    def test_ptp_timestamp_ns_conversion_roundtrip(self) -> None:
        total_ns = 1_234_567_890_123
        ts = PtpTimestamp.from_ns(total_ns)
        assert ts.seconds == 1234
        assert ts.nanoseconds == 567_890_123
        assert ts.to_ns() == total_ns

    def test_ptp_timestamp_float_seconds_conversion(self) -> None:
        f_sec = 42.125
        ts = PtpTimestamp.from_float_seconds(f_sec)
        assert ts.seconds == 42
        assert ts.nanoseconds == 125_000_000
        assert pytest.approx(ts.to_float_seconds(), abs=1e-9) == 42.125

    def test_ptp_timestamp_arithmetic_add_sub(self) -> None:
        ts = PtpTimestamp(seconds=100, nanoseconds=500_000_000)
        # Add nanoseconds as int
        ts_plus = ts + 600_000_000
        assert ts_plus.seconds == 101
        assert ts_plus.nanoseconds == 100_000_000

        # Sub nanoseconds as int
        ts_minus = ts - 600_000_000
        assert ts_minus.seconds == 99
        assert ts_minus.nanoseconds == 900_000_000

        # Add float seconds
        ts_plus_float = ts + 1.5
        assert ts_plus_float.seconds == 102
        assert ts_plus_float.nanoseconds == 0

    def test_ptp_timestamp_subtraction_interval(self) -> None:
        t1 = PtpTimestamp(seconds=100, nanoseconds=100_000)
        t2 = PtpTimestamp(seconds=100, nanoseconds=105_000)
        diff = t2 - t1
        assert isinstance(diff, PtpTimeInterval)
        assert int(diff) == 5000
        assert diff.seconds == 0
        assert diff.nanoseconds == 5000
        assert diff.to_ns() == 5000
        assert diff.to_float_seconds() == 5e-6

    def test_ptp_timestamp_floordiv_and_int_conversions(self) -> None:
        ts = PtpTimestamp(seconds=10, nanoseconds=0)
        half = ts // 2
        assert half.seconds == 5
        assert half.nanoseconds == 0
        assert int(ts) == 10_000_000_000

    def test_ptp_timestamp_wire_pack_unpack_roundtrip(self) -> None:
        ts = PtpTimestamp(seconds=0x0001_0002_0003, nanoseconds=987_654_321)
        packed = ts.pack()
        assert len(packed) == 10
        unpacked = PtpTimestamp.unpack(packed)
        assert unpacked.seconds == ts.seconds
        assert unpacked.nanoseconds == ts.nanoseconds

    def test_ptp_timestamp_unpack_invalid_length(self) -> None:
        with pytest.raises(ValueError, match="requires 10 bytes"):
            PtpTimestamp.unpack(b"\x00" * 9)


# ============================================================================
# Section 2: Clock Identity & Clock Quality
# ============================================================================

class TestPtpClockIdentityAndQuality:
    """Tests for EUI-64 Clock Identity generation and Clock Quality descriptors."""

    def test_clock_identity_default_eui64(self) -> None:
        cid = PtpClockIdentity.default_local()
        assert cid.to_hex() == "00-1D-9C-FF-FE-12-34-56"
        assert len(cid.raw_bytes) == 8
        assert str(cid) == "00-1D-9C-FF-FE-12-34-56"

    def test_clock_identity_from_mac_eui48_to_eui64(self) -> None:
        # Horner APG MAC address: 00:1D:9C:11:22:33
        cid = PtpClockIdentity.from_mac("00-1D-9C-11-22-33")
        assert cid.to_hex() == "00-1D-9C-FF-FE-11-22-33"
        # Colon formatted MAC
        cid2 = PtpClockIdentity.from_mac("00:1D:9C:44:55:66")
        assert cid2.to_hex() == "00-1D-9C-FF-FE-44-55-66"

    def test_clock_identity_from_hex_string_and_bytes(self) -> None:
        cid_bytes = bytes([1, 2, 3, 4, 5, 6, 7, 8])
        cid = PtpClockIdentity(cid_bytes)
        assert cid.raw_bytes == cid_bytes
        assert cid.to_int() == int.from_bytes(cid_bytes, "big")

        cid_hex = PtpClockIdentity("01-02-03-04-05-06-07-08")
        assert cid == cid_hex

    def test_clock_identity_comparisons_and_hashing(self) -> None:
        cid1 = PtpClockIdentity("00-00-00-00-00-00-00-01")
        cid2 = PtpClockIdentity("00-00-00-00-00-00-00-02")
        assert cid1 < cid2
        assert cid2 > cid1
        assert cid1 <= cid2
        assert cid2 >= cid1
        assert cid1 != cid2

        s = {cid1, cid2}
        assert len(s) == 2
        assert cid1 in s

    def test_clock_identity_invalid_inputs(self) -> None:
        with pytest.raises(ValueError):
            PtpClockIdentity(b"\x00" * 7)
        with pytest.raises(ValueError):
            PtpClockIdentity("00-11-22")
        with pytest.raises(TypeError):
            PtpClockIdentity(3.14)  # type: ignore

    def test_clock_quality_pack_unpack_and_comparison(self) -> None:
        cq1 = PtpClockQuality(clockClass=6, clockAccuracy=0x20, offsetScaledLogVariance=0x4000)
        cq2 = PtpClockQuality(clockClass=248, clockAccuracy=0xFE, offsetScaledLogVariance=0xFFFF)
        assert cq1 < cq2
        assert cq2 > cq1
        assert cq1 <= cq2
        assert cq2 >= cq1

        packed = cq1.pack()
        assert len(packed) == 4
        unpacked = PtpClockQuality.unpack(packed)
        assert unpacked.clockClass == 6
        assert unpacked.clockAccuracy == 0x20
        assert unpacked.offsetScaledLogVariance == 0x4000

    def test_port_identity_pack_unpack(self) -> None:
        cid = PtpClockIdentity("00-11-22-33-44-55-66-77")
        pid = PtpPortIdentity(clockIdentity=cid, portNumber=2)
        packed = pid.pack()
        assert len(packed) == 10
        unpacked = PtpPortIdentity.unpack(packed)
        assert unpacked.clockIdentity == cid
        assert unpacked.portNumber == 2


# ============================================================================
# Section 3: Best Master Clock Algorithm (BMCA)
# ============================================================================

class TestBMCAAlgorithm:
    """Tests for IEEE 1588-2008 clause 9.3.4 dataset comparisons."""

    @pytest.fixture
    def base_dataset(self) -> PtpDataset:
        return PtpDataset(
            priority1=128,
            clockQuality=PtpClockQuality(clockClass=248, clockAccuracy=0xFE, offsetScaledLogVariance=0xFFFF),
            priority2=128,
            clockIdentity=PtpClockIdentity("00-11-22-33-44-55-66-02"),
            stepsRemoved=0,
        )

    def test_bmca_priority1_wins(self, base_dataset: PtpDataset) -> None:
        ds_better = PtpDataset(
            priority1=100,
            clockQuality=base_dataset.clockQuality,
            priority2=base_dataset.priority2,
            clockIdentity=base_dataset.clockIdentity,
        )
        assert BMCA.compare_datasets(ds_better, base_dataset) == -1
        assert BMCA.compare_datasets(base_dataset, ds_better) == 1

    def test_bmca_clock_class_wins(self, base_dataset: PtpDataset) -> None:
        ds_better = PtpDataset(
            priority1=128,
            clockQuality=PtpClockQuality(clockClass=int(PtpClockClass.PRIMARY_REF), clockAccuracy=0xFE, offsetScaledLogVariance=0xFFFF),
            priority2=128,
            clockIdentity=base_dataset.clockIdentity,
        )
        assert BMCA.compare_datasets(ds_better, base_dataset) == -1
        assert BMCA.compare_datasets(base_dataset, ds_better) == 1

    def test_bmca_accuracy_wins(self, base_dataset: PtpDataset) -> None:
        ds_better = PtpDataset(
            priority1=128,
            clockQuality=PtpClockQuality(clockClass=248, clockAccuracy=0x20, offsetScaledLogVariance=0xFFFF),
            priority2=128,
            clockIdentity=base_dataset.clockIdentity,
        )
        assert BMCA.compare_datasets(ds_better, base_dataset) == -1
        assert BMCA.compare_datasets(base_dataset, ds_better) == 1

    def test_bmca_variance_wins(self, base_dataset: PtpDataset) -> None:
        ds_better = PtpDataset(
            priority1=128,
            clockQuality=PtpClockQuality(clockClass=248, clockAccuracy=0xFE, offsetScaledLogVariance=0x4000),
            priority2=128,
            clockIdentity=base_dataset.clockIdentity,
        )
        assert BMCA.compare_datasets(ds_better, base_dataset) == -1
        assert BMCA.compare_datasets(base_dataset, ds_better) == 1

    def test_bmca_priority2_wins(self, base_dataset: PtpDataset) -> None:
        ds_better = PtpDataset(
            priority1=128,
            clockQuality=base_dataset.clockQuality,
            priority2=64,
            clockIdentity=base_dataset.clockIdentity,
        )
        assert BMCA.compare_datasets(ds_better, base_dataset) == -1
        assert BMCA.compare_datasets(base_dataset, ds_better) == 1

    def test_bmca_steps_removed_wins(self, base_dataset: PtpDataset) -> None:
        ds_hop1 = PtpDataset(
            priority1=128,
            clockQuality=base_dataset.clockQuality,
            priority2=128,
            clockIdentity=base_dataset.clockIdentity,
            stepsRemoved=1,
        )
        ds_hop2 = PtpDataset(
            priority1=128,
            clockQuality=base_dataset.clockQuality,
            priority2=128,
            clockIdentity=base_dataset.clockIdentity,
            stepsRemoved=2,
        )
        assert BMCA.compare_datasets(ds_hop1, ds_hop2) == -1
        assert BMCA.compare_datasets(ds_hop2, ds_hop1) == 1

    def test_bmca_identity_tie_breaker_wins(self) -> None:
        ds1 = PtpDataset(
            priority1=128,
            clockQuality=PtpClockQuality(248, 0xFE, 0xFFFF),
            priority2=128,
            clockIdentity=PtpClockIdentity("00-00-00-00-00-00-00-01"),
        )
        ds2 = PtpDataset(
            priority1=128,
            clockQuality=PtpClockQuality(248, 0xFE, 0xFFFF),
            priority2=128,
            clockIdentity=PtpClockIdentity("00-00-00-00-00-00-00-02"),
        )
        assert BMCA.compare_datasets(ds1, ds2) == -1
        assert BMCA.compare_datasets(ds2, ds1) == 1

    def test_bmca_identical_datasets_tie(self, base_dataset: PtpDataset) -> None:
        assert BMCA.compare_datasets(base_dataset, base_dataset) == 0

    def test_bmca_select_master_foreign_election(self, base_dataset: PtpDataset) -> None:
        foreign = PtpDataset(
            priority1=128,
            clockQuality=PtpClockQuality(clockClass=int(PtpClockClass.PRIMARY_REF)),
            priority2=128,
            clockIdentity=PtpClockIdentity("00-11-22-33-44-55-66-01"),
        )
        best, is_local = BMCA.select_master(base_dataset, [foreign])
        assert best is foreign
        assert is_local is False

    def test_bmca_select_master_local_retains_master(self, base_dataset: PtpDataset) -> None:
        foreign_inferior = PtpDataset(
            priority1=200,
            clockQuality=base_dataset.clockQuality,
            priority2=200,
            clockIdentity=PtpClockIdentity("FF-FF-FF-FF-FF-FF-FF-FF"),
        )
        best, is_local = BMCA.select_master(base_dataset, [foreign_inferior])
        assert best is base_dataset
        assert is_local is True


# ============================================================================
# Section 4: PTP Wire Messages
# ============================================================================

class TestPtpWireMessages:
    """Tests for message header construction, packing, and message types."""

    def test_ptp_header_create_and_pack(self) -> None:
        cid = PtpClockIdentity.default_local()
        hdr = PtpHeader.create(PtpMessageType.SYNC, source_identity=cid, sequence_id=10, two_step=True)
        assert hdr.messageType == PtpMessageType.SYNC
        assert hdr.versionPTP == PTP_VERSION
        assert bool(hdr.flagField & int(PtpFlagField.TWO_STEP)) is True
        packed = hdr.pack()
        assert len(packed) >= 34

    def test_sync_message_creation_and_fields(self) -> None:
        hdr = PtpHeader.create(PtpMessageType.SYNC, PtpClockIdentity.default_local(), sequence_id=1)
        ts = PtpTimestamp(seconds=100, nanoseconds=50)
        msg = PtpSyncMessage(header=hdr, originTimestamp=ts)
        assert msg.header.sequenceId == 1
        assert msg.originTimestamp.seconds == 100

    def test_follow_up_message_creation_and_fields(self) -> None:
        hdr = PtpHeader.create(PtpMessageType.FOLLOW_UP, PtpClockIdentity.default_local(), sequence_id=1)
        ts = PtpTimestamp(seconds=100, nanoseconds=50)
        msg = PtpFollowUpMessage(header=hdr, preciseOriginTimestamp=ts)
        assert msg.preciseOriginTimestamp.nanoseconds == 50

    def test_delay_req_message_creation_and_fields(self) -> None:
        hdr = PtpHeader.create(PtpMessageType.DELAY_REQ, PtpClockIdentity.default_local(), sequence_id=5)
        ts = PtpTimestamp(seconds=101, nanoseconds=0)
        msg = PtpDelayReqMessage(header=hdr, originTimestamp=ts)
        assert msg.header.messageType == PtpMessageType.DELAY_REQ

    def test_delay_resp_message_creation_and_fields(self) -> None:
        hdr = PtpHeader.create(PtpMessageType.DELAY_RESP, PtpClockIdentity.default_local(), sequence_id=5)
        t4 = PtpTimestamp(seconds=101, nanoseconds=4000)
        msg = PtpDelayRespMessage(header=hdr, receiveTimestamp=t4)
        assert msg.receiveTimestamp == t4

    def test_announce_message_to_dataset_conversion(self) -> None:
        hdr = PtpHeader.create(PtpMessageType.ANNOUNCE, PtpClockIdentity.default_local(), sequence_id=1)
        cq = PtpClockQuality(clockClass=6, clockAccuracy=0x20, offsetScaledLogVariance=0x4000)
        ann = PtpAnnounceMessage(
            header=hdr,
            grandmasterPriority1=128,
            grandmasterClockQuality=cq,
            grandmasterPriority2=128,
            grandmasterIdentity=PtpClockIdentity.default_local(),
            stepsRemoved=0,
        )
        ds = ann.to_dataset()
        assert ds.priority1 == 128
        assert ds.clockQuality.clockClass == 6
        assert ds.clockIdentity == PtpClockIdentity.default_local()


# ============================================================================
# Section 5: Two-Step Timing and Path Delay Equations
# ============================================================================

class TestTwoStepTimingAndPathDelay:
    """Tests for two-step timestamp processing and mean path delay calculation."""

    @pytest.fixture
    def slave_engine(self) -> CipSyncPtpEngine:
        return CipSyncPtpEngine(clock_identity="00-11-22-33-44-55-66-88")

    def test_two_step_sync_and_follow_up_timestamp_capture(self, slave_engine: CipSyncPtpEngine) -> None:
        cid_master = PtpClockIdentity("00-AA-BB-CC-DD-EE-FF-01")
        t1 = PtpTimestamp(seconds=1000, nanoseconds=100_000)
        t2 = PtpTimestamp(seconds=1000, nanoseconds=105_000)

        # Sync arrives at t2
        hdr_sync = PtpHeader.create(PtpMessageType.SYNC, cid_master, sequence_id=10, two_step=True)
        sync_msg = PtpSyncMessage(header=hdr_sync)
        t2_out = slave_engine.process_sync(sync_msg, ingress_timestamp=t2)
        assert t2_out == t2
        assert slave_engine.t2 == t2

        # Follow_up delivers t1
        hdr_fu = PtpHeader.create(PtpMessageType.FOLLOW_UP, cid_master, sequence_id=10, two_step=True)
        fu_msg = PtpFollowUpMessage(header=hdr_fu, preciseOriginTimestamp=t1)
        res = slave_engine.process_follow_up(fu_msg)
        assert res is True
        assert slave_engine.t1 == t1

    def test_follow_up_sequence_mismatch_ignored(self, slave_engine: CipSyncPtpEngine) -> None:
        cid_master = PtpClockIdentity("00-AA-BB-CC-DD-EE-FF-01")
        hdr_sync = PtpHeader.create(PtpMessageType.SYNC, cid_master, sequence_id=10, two_step=True)
        slave_engine.process_sync(PtpSyncMessage(header=hdr_sync))

        # Follow-up with wrong sequence ID 99
        hdr_fu = PtpHeader.create(PtpMessageType.FOLLOW_UP, cid_master, sequence_id=99, two_step=True)
        res = slave_engine.process_follow_up(PtpFollowUpMessage(header=hdr_fu))
        assert res is False

    def test_send_delay_req_increments_sequence_and_stamps_t3(self, slave_engine: CipSyncPtpEngine) -> None:
        t3 = PtpTimestamp(seconds=1000, nanoseconds=200_000)
        msg1, t3_rec1 = slave_engine.send_delay_req(egress_timestamp=t3)
        assert msg1.header.sequenceId == 1
        assert t3_rec1 == t3
        assert slave_engine.t3 == t3

        msg2, _ = slave_engine.send_delay_req()
        assert msg2.header.sequenceId == 2

    def test_canonical_path_delay_and_offset_equations(self, slave_engine: CipSyncPtpEngine) -> None:
        # t1: Master sends Sync at 1000.000100000 s
        # t2: Slave receives Sync at 1000.000105200 s (t2 - t1 = 5,200 ns)
        # t3: Slave sends Delay_Req at 1001.000200000 s
        # t4: Master receives Delay_Req at 1001.000204800 s (t4 - t3 = 4,800 ns)
        # mean_path_delay = ((t2 - t1) + (t4 - t3)) // 2 = (5200 + 4800) // 2 = 5,000 ns
        # offset_from_master = (t2 - t1) - mean_path_delay = 5200 - 5000 = +200 ns
        slave_engine.t1 = PtpTimestamp(seconds=1000, nanoseconds=100_000)
        slave_engine.t2 = PtpTimestamp(seconds=1000, nanoseconds=105_200)
        slave_engine.t3 = PtpTimestamp(seconds=1001, nanoseconds=200_000)

        t4 = PtpTimestamp(seconds=1001, nanoseconds=204_800)
        hdr = PtpHeader.create(PtpMessageType.DELAY_RESP, PtpClockIdentity.default_local(), sequence_id=1)
        resp = PtpDelayRespMessage(header=hdr, receiveTimestamp=t4)

        res = slave_engine.process_delay_resp(resp)
        assert res["mean_path_delay_ns"] == 5000
        assert res["offset_from_master_ns"] == 200
        assert slave_engine.mean_path_delay_ns == 5000
        assert slave_engine.offset_from_master_ns == 200

    def test_asymmetric_delay_calculation(self, slave_engine: CipSyncPtpEngine) -> None:
        # t2 - t1 = 12,000 ns, t4 - t3 = 8,000 ns
        # mean_delay = (12000 + 8000) // 2 = 10,000 ns
        # offset = 12000 - 10000 = +2000 ns
        slave_engine.t1 = PtpTimestamp(100, 0)
        slave_engine.t2 = PtpTimestamp(100, 12_000)
        slave_engine.t3 = PtpTimestamp(200, 0)
        resp = PtpDelayRespMessage(
            header=PtpHeader.create(PtpMessageType.DELAY_RESP, PtpClockIdentity.default_local(), sequence_id=1),
            receiveTimestamp=PtpTimestamp(200, 8000),
        )
        res = slave_engine.process_delay_resp(resp)
        assert res["mean_path_delay_ns"] == 10_000
        assert res["offset_from_master_ns"] == 2000

    def test_incomplete_timestamps_handled_safely(self, slave_engine: CipSyncPtpEngine) -> None:
        slave_engine.t1 = None
        resp = PtpDelayRespMessage(
            header=PtpHeader.create(PtpMessageType.DELAY_RESP, PtpClockIdentity.default_local(), sequence_id=1),
            receiveTimestamp=PtpTimestamp(200, 8000),
        )
        res = slave_engine.process_delay_resp(resp)
        assert res["status"] == "incomplete_timestamps"


# ============================================================================
# Section 6: PI Clock Servo Controller
# ============================================================================

class TestPtpServoAndDriftAdjustment:
    """Tests for PI clock frequency steering, phase step vs slewing, and jitter clamping."""

    def test_servo_initialization_and_reset(self) -> None:
        servo = PtpServo(kp=0.2, ki=0.01)
        servo.integral_error = 500.0
        servo.frequency_drift_ppb = 50
        servo.is_locked = True
        servo.reset()
        assert servo.integral_error == 0.0
        assert servo.frequency_drift_ppb == 0
        assert servo.is_locked is False

    def test_servo_coarse_phase_step_on_large_offset(self) -> None:
        servo = PtpServo(step_threshold_ns=100_000)
        # Phase error 250,000 ns > 100,000 ns threshold -> step adjustment
        drift, adj = servo.sample(250_000, dt=1.0)
        assert adj == 250_000
        assert servo.integral_error == 0.0
        assert servo.is_locked is False

    def test_servo_fine_slewing_pi_control(self) -> None:
        servo = PtpServo(kp=0.1, ki=0.01, step_threshold_ns=100_000)
        drift, adj = servo.sample(500, dt=0.5)
        # adj = round(0.1 * 500) = 50
        assert adj == 50
        # integral_error = 500 * 0.5 = 250.0
        # raw_drift = 0.01 * 250 = 2.5 -> round-half-to-even gives 2
        assert drift == 2
        assert servo.is_locked is True

    def test_servo_drift_ppb_clamping(self) -> None:
        servo = PtpServo(ki=10.0, max_drift_ppb=MAX_SERVO_DRIFT_PPB)
        servo.integral_error = 100_000.0
        drift, _ = servo.sample(10_000, dt=1.0)
        assert drift == MAX_SERVO_DRIFT_PPB

    def test_servo_convergence_on_residual_error(self) -> None:
        servo = PtpServo(kp=0.2, ki=0.01)
        offset = 600
        for _ in range(30):
            drift, adj = servo.sample(offset, dt=0.125)
            offset -= adj
        assert abs(offset) < 10
        assert servo.is_locked is True

    def test_servo_jitter_spike_filtering_and_clamping(self) -> None:
        servo = PtpServo(kp=0.1, jitter_spike_threshold_ns=20_000)
        drift, adj = servo.sample(80_000, dt=0.125)
        assert servo.jitter_spike_count == 1
        # Clamped to 20,000 -> adj = round(0.1 * 20_000) = 2000
        assert adj == 2000


# ============================================================================
# Section 7: Pure IEC 61131-3 ST POU & SecurityGuard
# ============================================================================

class TestPureStPouAndSecurityGuard:
    """Tests for STParser validation and anti-ladder security enforcement."""

    def test_cip_sync_ptp_pure_st_pou_validates_cleanly(self) -> None:
        res = STParser.validate_code(CIP_SYNC_PTP_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS

    def test_cip_sync_ptp_ast_register_bindings(self) -> None:
        ast = STParser.parse_pou(CIP_SYNC_PTP_SYNC_POU)
        assert ast.name == "CipSyncPtpSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R1480", "%R1481", "%R1482", "%R1483",
            "%R1484", "%R1485", "%R1486", "%R1487",
            "%M345", "%M346",
        }
        assert expected_regs.issubset(set(ast.bound_registers))

    def test_security_guard_assert_pure_st_clean_pass(self) -> None:
        # Valid pure ST code must not raise LadderForbiddenError
        SecurityGuard.assert_pure_st_content(CIP_SYNC_PTP_SYNC_POU)

    def test_security_guard_rejects_ladder_contacts(self) -> None:
        bad_st = f"{CIP_SYNC_PTP_SYNC_POU}\n---[ ]---"
        with pytest.raises(LadderForbiddenError, match="ERR_LADDER_FORBIDDEN"):
            SecurityGuard.assert_pure_st_content(bad_st)

        bad_neg_contact = f"{CIP_SYNC_PTP_SYNC_POU}\n---[/]---"
        with pytest.raises(LadderForbiddenError, match="ERR_LADDER_FORBIDDEN"):
            SecurityGuard.assert_pure_st_content(bad_neg_contact)

    def test_security_guard_rejects_ladder_coils(self) -> None:
        for coil in ["---( )---", "---(S)---", "---(R)---"]:
            bad_st = f"{CIP_SYNC_PTP_SYNC_POU}\n{coil}"
            with pytest.raises(LadderForbiddenError, match="ERR_LADDER_FORBIDDEN"):
                SecurityGuard.assert_pure_st_content(bad_st)

    def test_security_guard_rejects_ladder_rungs(self) -> None:
        bad_st = f"{CIP_SYNC_PTP_SYNC_POU}\nRUNG 1\nNETWORK 1"
        with pytest.raises(LadderForbiddenError, match="ERR_LADDER_FORBIDDEN"):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_security_guard_rejects_ladder_mnemonics(self) -> None:
        for mnemonic in ["XIC PtpLock", "OTE GrandmasterFlag", "OTL LatchedFault"]:
            bad_st = f"{CIP_SYNC_PTP_SYNC_POU}\n{mnemonic}"
            with pytest.raises(LadderForbiddenError, match="ERR_LADDER_FORBIDDEN"):
                SecurityGuard.assert_pure_st_content(bad_st)


# ============================================================================
# Section 8: Horner OCS Register Table Synchronization
# ============================================================================

class TestRegisterTableSynchronization:
    """Tests for Horner %R1480..%R1487, %M345..%M346 register mapping with SYSTEM privilege."""

    @pytest.fixture
    def reg_table(self) -> RegisterTable:
        return RegisterTable()

    def test_register_table_sync_with_system_privilege(self, reg_table: RegisterTable) -> None:
        engine = CipSyncPtpEngine(reg_table=reg_table, clock_class=PtpClockClass.PRIMARY_REF)
        engine.state = PtpPortState.SLAVE
        engine.offset_from_master_ns = 250_000  # 250 us
        engine.mean_path_delay_ns = 4_000       # 4 us
        engine.frequency_drift_ppb = -15
        engine.message_counter = 120
        engine.diagnostic_code = PtpDiagnosticCode.OK
        engine.sync_threshold_ns = 500_000

        engine.sync_to_registers()

        assert reg_table.read_word("%R1480") == int(PtpPortState.SLAVE)
        # Reconstruct 32-bit DINT offset
        offset_us = decode_dint_words(reg_table.read_word("%R1481"), reg_table.read_word("%R1482"))
        assert offset_us == 250
        assert reg_table.read_word("%R1483") == 4
        assert reg_table.read_word("%R1484") == -15
        assert reg_table.read_word("%R1485") == int(PtpClockClass.PRIMARY_REF)
        assert reg_table.read_word("%R1486") == 120
        assert reg_table.read_uword("%R1487") == 0x0000
        assert reg_table.read_bit("%M345") is True
        assert reg_table.read_bit("%M346") is False

    def test_dint_32bit_words_encoding_and_decoding(self) -> None:
        # Positive 32-bit value: 500,000 us
        h, l = encode_dint_words(500_000)
        decoded = decode_dint_words(h, l)
        assert decoded == 500_000

    def test_negative_master_offset_dint_encoding(self, reg_table: RegisterTable) -> None:
        # Negative offset: -125,000 us (-125 ms)
        h, l = encode_dint_words(-125_000)
        decoded = decode_dint_words(h, l)
        assert decoded == -125_000

        safe_write_word(reg_table, "%R1481", h)
        safe_write_word(reg_table, "%R1482", l)
        assert decode_dint_words(reg_table.read_word("%R1481"), reg_table.read_word("%R1482")) == -125_000

    def test_sync_flag_m345_and_gm_flag_m346_coils(self, reg_table: RegisterTable) -> None:
        engine = CipSyncPtpEngine(reg_table=reg_table)
        # In MASTER state, GM flag is asserted
        engine.state = PtpPortState.MASTER
        engine.sync_to_registers()
        assert reg_table.read_bit("%M345") is True
        assert reg_table.read_bit("%M346") is True

        # In FAULTY state, sync flag is cleared
        engine.state = PtpPortState.FAULTY
        engine.diagnostic_code = PtpDiagnosticCode.SYNC_TIMEOUT
        engine.sync_to_registers()
        assert reg_table.read_bit("%M345") is False
        assert reg_table.read_bit("%M346") is False

    def test_message_counter_wrapping_in_r1486(self, reg_table: RegisterTable) -> None:
        engine = CipSyncPtpEngine(reg_table=reg_table)
        engine.message_counter = 0x8005
        engine.sync_to_registers()
        # Clamped/masked to 15-bit INT16 range
        assert reg_table.read_word("%R1486") == 5


# ============================================================================
# Section 9: ILogicUnit 100-Cycle Simulation
# ============================================================================

class TestILogicUnitScanCycle:
    """Tests for discrete simulation cycle execution and clock drift steering."""

    @pytest.fixture
    def sim_engine(self) -> CipSyncPtpEngine:
        rt = RegisterTable()
        return CipSyncPtpEngine(reg_table=rt)

    def test_ilogic_unit_interface_properties(self, sim_engine: CipSyncPtpEngine) -> None:
        assert isinstance(sim_engine, ILogicUnit)
        assert sim_engine.name == "cip_sync_ptp"
        assert sim_engine.priority == 92
        assert sim_engine.is_enabled is True

    def test_scan_step_clock_progression_and_drift_steering(self, sim_engine: CipSyncPtpEngine) -> None:
        t_init = sim_engine.local_clock.to_ns()
        # +1000 ppb drift (+1 us per second)
        sim_engine.frequency_drift_ppb = 1000
        step_res = sim_engine.scan_step(dt=1.0)
        t_after = sim_engine.local_clock.to_ns()
        elapsed_ns = t_after - t_init
        # Nominal 1.0s = 1,000,000,000 ns + 1000 ns drift = 1,000,001,000 ns
        assert elapsed_ns == 1_000_001_000
        assert step_res["state"] == sim_engine.state.name

    def test_execute_100_scan_cycles_simulation(self, sim_engine: CipSyncPtpEngine) -> None:
        rt = sim_engine.reg_table
        assert rt is not None
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

        for c in range(1, 101):
            ctx.cycle = c
            ctx.elapsed_time_ms = c * 10.0
            sim_engine.execute(ctx)

        assert sim_engine.total_scan_cycles == 100
        assert round(sim_engine.elapsed_simulation_ms) == 1000

    def test_engine_reset_restores_clean_state(self, sim_engine: CipSyncPtpEngine) -> None:
        sim_engine.simulate_sync_timeout()
        assert sim_engine.state == PtpPortState.FAULTY
        sim_engine.reset()
        assert sim_engine.diagnostic_code == PtpDiagnosticCode.OK
        assert sim_engine.time_since_last_sync_s == 0.0


# ============================================================================
# Section 10: Fault Scenarios & Process Safety Interlocks
# ============================================================================

class TestFaultScenariosAndDiagnostics:
    """Tests for fault simulation trips (0xD101..0xD104) and operator reset."""

    @pytest.fixture
    def fault_engine(self) -> CipSyncPtpEngine:
        rt = RegisterTable()
        return CipSyncPtpEngine(reg_table=rt)

    def test_fault_bmca_lost_grandmaster_timeout(self, fault_engine: CipSyncPtpEngine) -> None:
        rt = fault_engine.reg_table
        assert rt is not None
        fault_engine.state = PtpPortState.SLAVE
        fault_engine.simulate_bmca_lost_gm()

        assert fault_engine.diagnostic_code == PtpDiagnosticCode.BMCA_LOST_GM
        assert fault_engine.state == PtpPortState.LISTENING
        assert fault_engine.is_synchronized is False
        assert rt.read_uword("%R1487") == 0xD101
        assert rt.read_bit("%M345") is False

    def test_fault_sync_message_timeout(self, fault_engine: CipSyncPtpEngine) -> None:
        rt = fault_engine.reg_table
        assert rt is not None
        fault_engine.state = PtpPortState.SLAVE
        fault_engine.simulate_sync_timeout()

        assert fault_engine.diagnostic_code == PtpDiagnosticCode.SYNC_TIMEOUT
        assert fault_engine.state == PtpPortState.FAULTY
        assert fault_engine.is_synchronized is False
        assert rt.read_uword("%R1487") == 0xD102
        assert rt.read_bit("%M345") is False

    def test_fault_high_jitter_spike_trip(self, fault_engine: CipSyncPtpEngine) -> None:
        rt = fault_engine.reg_table
        assert rt is not None
        fault_engine.simulate_jitter_spike(75_000)

        assert fault_engine.diagnostic_code == PtpDiagnosticCode.JITTER_SPIKE
        assert fault_engine.is_synchronized is False
        assert rt.read_uword("%R1487") == 0xD103
        assert rt.read_bit("%M345") is False

    def test_fault_hardware_lockout_interception(self, fault_engine: CipSyncPtpEngine) -> None:
        rt = fault_engine.reg_table
        assert rt is not None
        # Simulating hardware lockout must exercise SecurityGuard port lockout on physical port
        fault_engine.simulate_hardware_lockout()

        assert fault_engine.diagnostic_code == PtpDiagnosticCode.HARDWARE_LOCKOUT
        assert fault_engine.state == PtpPortState.FAULTY
        assert fault_engine.is_synchronized is False
        assert rt.read_uword("%R1487") == 0xD104
        assert rt.read_word("%R1480") == int(PtpPortState.FAULTY)
        assert rt.read_bit("%M345") is False

    def test_operator_reset_handshake_restores_health(self, fault_engine: CipSyncPtpEngine) -> None:
        rt = fault_engine.reg_table
        assert rt is not None
        fault_engine.simulate_sync_timeout()
        assert fault_engine.diagnostic_code != PtpDiagnosticCode.OK

        res = fault_engine.reset_fault(force=True)
        assert res.status == AgentStatus.SUCCESS
        assert fault_engine.diagnostic_code == PtpDiagnosticCode.OK
        assert rt.read_uword("%R1487") == 0x0000


# ============================================================================
# Section 11: Deterministic 9-Stage Verification Suite
# ============================================================================

class TestDeterministicVerificationRunner:
    """Tests for the complete 9-stage verification runner function."""

    def test_run_cip_sync_ptp_verification_returns_success(self) -> None:
        res = run_cip_sync_ptp_verification()
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["stages_passed"] == 9
        assert res["total_stages"] == 9

        # Ensure all 9 stages passed individually
        stages = res["data"]["stages"]
        assert len(stages) == 9
        for stage in stages:
            assert stage["passed"] is True, f"Stage {stage['stage']} ({stage['check']}) failed!"

    def test_run_cip_sync_ptp_verification_evidence_file_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "test_evidence.json"
            res = run_cip_sync_ptp_verification(output_path=out_file)
            assert res["status"] == "success"
            assert out_file.exists()

            with open(out_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["stages_passed"] == 9
            assert loaded["data"]["work_package"] == "W187"
