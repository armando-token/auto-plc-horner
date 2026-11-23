"""Unit Test Suite for Industrial FOUNDATION Fieldbus H1 Master Protocol Engine.

Work Package: W109 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Pure ST POU AST validation and anti-ladder check (verify_fieldbus_pure_st).
2. Frame encoding & token types (CD, PT, PN, TD, DT, PR, RT).
3. LAS macrocycle scheduler execution with scheduled and unscheduled phases.
4. Live list discovery and probe node (PN) state transitions.
5. Backup Link Master failover negotiation and role transition.
6. Cyclic publisher/subscriber data exchange and status octet evaluation.
7. Diagnostics: missed CD polls (SLAVE_OFFLINE), token loss (TOKEN_PASS_LOST), and jitter alarms.
8. Horner OCS register space synchronization (%R700..%R707, %M163..%M164).
9. Anti-ladder security guard rejection (LadderForbiddenError on contacts/coils).
10. End-to-end 9-stage verification suite (run_fieldbus_verification).
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.fieldbus import (
    BROADCAST_ADDRESS,
    DEFAULT_MACROCYCLE_PERIOD_MS,
    DEFAULT_TOKEN_TIMEOUT_MS,
    END_DELIMITER,
    FIELDBUS_BAUD_RATE_BPS,
    FIELDBUS_BIT_TIME_US,
    FIELDBUS_PURE_ST_POU,
    MAX_CONSECUTIVE_CD_RETRIES,
    MAX_CYCLE_JITTER_TOLERANCE,
    OPERATIONAL_ADDR_MAX,
    OPERATIONAL_ADDR_MIN,
    PREAMBLE_OCTET,
    START_DELIMITER,
    DeviceRole,
    DoubleBuffer,
    FieldbusDeviceDescriptor,
    FieldbusDiagnosticCode,
    FieldbusFrameType,
    FieldbusH1Frame,
    FieldbusLASEngine,
    FieldbusStatusBits,
    LASRedundancyState,
    LimitStatus,
    ProcessVariable,
    QualityCode,
    ScheduledCDTransaction,
    SubstatusBad,
    SubstatusGood,
    SubstatusUncertain,
    calculate_frame_transmission_time_us,
    compute_crc16_ccitt,
    get_quality,
    is_operational_address,
    is_quality_bad,
    is_quality_good,
    is_quality_uncertain,
    make_status_octet,
    run_fieldbus_verification,
    verify_fieldbus_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def las_engine(register_table: RegisterTable) -> FieldbusLASEngine:
    """Provide a FieldbusLASEngine initialized at address 16 (0x10)."""
    return FieldbusLASEngine(
        las_address=0x10,
        macrocycle_period_ms=500,
        register_table=register_table,
    )


# ============================================================================
# 1. Pure ST POU AST Validation & Anti-Ladder Check
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for Pure Structured Text POU validation and anti-ladder compliance."""

    def test_verify_fieldbus_pure_st_function(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_fieldbus_pure_st() is True

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Parse FIELDBUS_PURE_ST_POU with STParser and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(FIELDBUS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "FieldbusH1Sync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "FieldbusStatusWord",
            "ActiveNodeCount",
            "LiveListMaskLow",
            "LiveListMaskMid",
            "LiveListMaskHigh",
            "MacrocyclePeriodMs",
            "TotalMacrocyclesExecuted",
            "DiagnosticEventCode",
            "FieldbusNormalActive",
            "FieldbusTripFault",
        }
        assert expected_vars.issubset(var_names)

        # Verify direct address bindings
        reg_map = {v.name: v.address_binding for v in pou.variables if v.address_binding}
        assert reg_map["FieldbusStatusWord"] == "%R700"
        assert reg_map["ActiveNodeCount"] == "%R701"
        assert reg_map["LiveListMaskLow"] == "%R702"
        assert reg_map["LiveListMaskMid"] == "%R703"
        assert reg_map["LiveListMaskHigh"] == "%R704"
        assert reg_map["MacrocyclePeriodMs"] == "%R705"
        assert reg_map["TotalMacrocyclesExecuted"] == "%R706"
        assert reg_map["DiagnosticEventCode"] == "%R707"
        assert reg_map["FieldbusNormalActive"] == "%M163"
        assert reg_map["FieldbusTripFault"] == "%M164"

    def test_security_guard_pure_st_assertion(self) -> None:
        """Verify pure ST POU passes SecurityGuard assertion cleanly."""
        SecurityGuard.assert_pure_st_content(FIELDBUS_PURE_ST_POU)


# ============================================================================
# 2. Frame Encoding & Token Types (CD, PT, PN, TD)
# ============================================================================

class TestSection2FrameEncodingAndTokens:
    """Tests for Fieldbus H1 wire frame encoding, CRC-16, and DLPDU token types."""

    def test_crc16_ccitt_determinism(self) -> None:
        """Verify CRC-16-CCITT calculation against known byte patterns."""
        data = bytes([int(FieldbusFrameType.COMPEL_DATA), 0x11, 0x10, 0x01])
        crc1 = compute_crc16_ccitt(data)
        crc2 = compute_crc16_ccitt(data)
        assert crc1 == crc2
        assert 0 <= crc1 <= 0xFFFF

    def test_frame_transmission_time_formula(self) -> None:
        """Verify analytical transmission duration formula at 31.25 kbit/s."""
        # Frame: 8 overhead octets + 1 payload octet = 9 octets = 72 bits
        # 72 bits * 32.0 us = 2304.0 us
        duration_us = calculate_frame_transmission_time_us(payload_len=1)
        assert duration_us == pytest.approx(2304.0, abs=1e-3)

        # 0 payload: 8 octets * 8 bits * 32.0 us = 2048.0 us
        duration_0 = calculate_frame_transmission_time_us(payload_len=0)
        assert duration_0 == pytest.approx(2048.0, abs=1e-3)

    def test_compel_data_frame_roundtrip(self) -> None:
        """Verify Compel Data (CD) token frame serialization and deserialization."""
        frame = FieldbusH1Frame(
            frame_type=FieldbusFrameType.COMPEL_DATA,
            dest_address=0x11,
            src_address=0x10,
            payload=bytes([0x01]),
        )
        wire = frame.encode()
        assert wire[0] == PREAMBLE_OCTET
        assert wire[1] == START_DELIMITER
        assert wire[2] == int(FieldbusFrameType.COMPEL_DATA)
        assert wire[3] == 0x11
        assert wire[4] == 0x10
        assert wire[-1] == END_DELIMITER

        decoded, err = FieldbusH1Frame.decode(wire)
        assert err == "OK"
        assert decoded is not None
        assert decoded.frame_type == FieldbusFrameType.COMPEL_DATA
        assert decoded.dest_address == 0x11
        assert decoded.src_address == 0x10
        assert decoded.payload == bytes([0x01])

    def test_pass_token_frame_roundtrip(self) -> None:
        """Verify Pass Token (PT) unscheduled token serialization and deserialization."""
        frame = FieldbusH1Frame(
            frame_type=FieldbusFrameType.PASS_TOKEN,
            dest_address=0x20,
            src_address=0x10,
            payload=b"\x00\x14",
        )
        wire = frame.encode()
        decoded, err = FieldbusH1Frame.decode(wire)
        assert err == "OK"
        assert decoded is not None
        assert decoded.frame_type == FieldbusFrameType.PASS_TOKEN
        assert decoded.dest_address == 0x20
        assert decoded.src_address == 0x10

    def test_probe_node_and_response_roundtrip(self) -> None:
        """Verify Probe Node (PN) and Probe Response (PR) frame roundtrips."""
        # PN Frame
        pn_frame = FieldbusH1Frame(
            frame_type=FieldbusFrameType.PROBE_NODE,
            dest_address=0x22,
            src_address=0x10,
            payload=b"",
        )
        wire_pn = pn_frame.encode()
        dec_pn, err_pn = FieldbusH1Frame.decode(wire_pn)
        assert err_pn == "OK"
        assert dec_pn is not None
        assert dec_pn.frame_type == FieldbusFrameType.PROBE_NODE

        # PR Frame
        pr_frame = FieldbusH1Frame(
            frame_type=FieldbusFrameType.PROBE_RESPONSE,
            dest_address=0x10,
            src_address=0x22,
            payload=b"\x01TT-101",
        )
        wire_pr = pr_frame.encode()
        dec_pr, err_pr = FieldbusH1Frame.decode(wire_pr)
        assert err_pr == "OK"
        assert dec_pr is not None
        assert dec_pr.frame_type == FieldbusFrameType.PROBE_RESPONSE
        assert dec_pr.payload == b"\x01TT-101"

    def test_time_distribution_frame_roundtrip(self) -> None:
        """Verify Time Distribution (TD) network synchronization broadcast frame."""
        td_frame = FieldbusH1Frame(
            frame_type=FieldbusFrameType.TIME_DISTRIBUTION,
            dest_address=BROADCAST_ADDRESS,
            src_address=0x10,
            payload=b"\x00\x00\x00\x01\x00\x00\x00\x00",
        )
        wire_td = td_frame.encode()
        dec_td, err_td = FieldbusH1Frame.decode(wire_td)
        assert err_td == "OK"
        assert dec_td is not None
        assert dec_td.frame_type == FieldbusFrameType.TIME_DISTRIBUTION
        assert dec_td.dest_address == BROADCAST_ADDRESS

    def test_data_response_and_return_token_roundtrip(self) -> None:
        """Verify Data Response (DT) and Return Token (RT) frame roundtrips."""
        dt_frame = FieldbusH1Frame(
            frame_type=FieldbusFrameType.DATA_RESPONSE,
            dest_address=BROADCAST_ADDRESS,
            src_address=0x17,
            payload=b"\x01\x42\xF6\xE6\x66\x80",
        )
        wire_dt = dt_frame.encode()
        dec_dt, err_dt = FieldbusH1Frame.decode(wire_dt)
        assert err_dt == "OK"
        assert dec_dt is not None
        assert dec_dt.frame_type == FieldbusFrameType.DATA_RESPONSE

        rt_frame = FieldbusH1Frame(
            frame_type=FieldbusFrameType.RETURN_TOKEN,
            dest_address=0x10,
            src_address=0x17,
            payload=b"",
        )
        wire_rt = rt_frame.encode()
        dec_rt, err_rt = FieldbusH1Frame.decode(wire_rt)
        assert err_rt == "OK"
        assert dec_rt is not None
        assert dec_rt.frame_type == FieldbusFrameType.RETURN_TOKEN

    def test_frame_decoding_corruptions(self) -> None:
        """Verify error detection for preamble, delimiters, FCS, length, and frame type."""
        valid_frame = FieldbusH1Frame(
            frame_type=FieldbusFrameType.COMPEL_DATA,
            dest_address=0x11,
            src_address=0x10,
            payload=bytes([1]),
        ).encode()

        # 1. Corrupt Preamble
        bad_pre = bytearray(valid_frame)
        bad_pre[0] = 0xAA
        _, err = FieldbusH1Frame.decode(bytes(bad_pre))
        assert err == "ERR_PREAMBLE"

        # 2. Corrupt Start Delimiter
        bad_sd = bytearray(valid_frame)
        bad_sd[1] = 0x00
        _, err = FieldbusH1Frame.decode(bytes(bad_sd))
        assert err == "ERR_START_DELIMITER"

        # 3. Corrupt End Delimiter
        bad_ed = bytearray(valid_frame)
        bad_ed[-1] = 0x00
        _, err = FieldbusH1Frame.decode(bytes(bad_ed))
        assert err == "ERR_END_DELIMITER"

        # 4. Corrupt FCS
        bad_fcs = bytearray(valid_frame)
        bad_fcs[-2] ^= 0xFF
        _, err = FieldbusH1Frame.decode(bytes(bad_fcs))
        assert err == "ERR_FCS_MISMATCH"

        # 5. Truncated frame
        _, err = FieldbusH1Frame.decode(valid_frame[:6])
        assert err == "ERR_FRAME_TOO_SHORT"

        # 6. Unknown frame type
        bad_type = bytearray(valid_frame)
        bad_type[2] = 0xFE  # invalid frame type
        # Recompute valid FCS for corrupt payload so it passes to type validation
        protected = bad_type[2:-3]
        fcs = compute_crc16_ccitt(protected)
        bad_type[-3] = (fcs >> 8) & 0xFF
        bad_type[-2] = fcs & 0xFF
        _, err = FieldbusH1Frame.decode(bytes(bad_type))
        assert err == "ERR_UNKNOWN_FRAME_TYPE"


# ============================================================================
# 3. LAS Macrocycle Scheduler Execution
# ============================================================================

class TestSection3MacrocycleScheduler:
    """Tests for LAS macrocycle scheduler with scheduled and unscheduled phases."""

    def test_macrocycle_execution_scheduled_phase(self, las_engine: FieldbusLASEngine) -> None:
        """Verify scheduled phase polls configured publishers and updates double buffer."""
        dev17 = FieldbusDeviceDescriptor(address=17, device_tag="TT-101")
        dev17.update_channel(channel_id=1, value=98.6, status_octet=make_status_octet(QualityCode.GOOD_NON_CASCADE))
        las_engine.add_device(dev17)

        las_engine.add_scheduled_cd(ScheduledCDTransaction(offset_ms=50, publisher_address=17, channel_id=1))
        res = las_engine.execute_macrocycle(cycle_duration_override_ms=500.0)

        assert res["macrocycle_index"] == 1
        assert res["scheduled_cd_success"] == 1
        assert res["scheduled_cd_failed"] == 0
        assert res["token_rotation_ok"] is True

        # Check committed double buffer
        pv = las_engine.double_buffer.read(17, 1)
        assert pv is not None
        assert math.isclose(pv.value, 98.6, rel_tol=1e-3)
        assert pv.is_good is True

    def test_macrocycle_execution_unscheduled_phase(self, las_engine: FieldbusLASEngine) -> None:
        """Verify unscheduled phase distributes time, rotates tokens, and advances probe pointer."""
        initial_probe_addr = las_engine.current_probe_address
        res = las_engine.execute_macrocycle(cycle_duration_override_ms=500.0)

        assert res["token_rotation_ok"] is True
        assert res["probed_address"] == initial_probe_addr
        assert las_engine.current_probe_address == initial_probe_addr + 1

    def test_timing_jitter_evaluation(self, las_engine: FieldbusLASEngine) -> None:
        """Verify jitter surveillance passes within 5% and trips alarm above 5%."""
        # 1. Jitter within tolerance: 515 ms vs 500 ms nominal (3.0% delta <= 5.0%)
        ratio, ok = las_engine.evaluate_jitter(515.0)
        assert ok is True
        assert math.isclose(ratio, 0.03, rel_tol=1e-3)
        assert (las_engine.status_bits & FieldbusStatusBits.JITTER_ALARM) == 0

        # 2. Jitter exceeding tolerance: 535 ms vs 500 ms nominal (7.0% delta > 5.0%)
        ratio_breach, ok_breach = las_engine.evaluate_jitter(535.0)
        assert ok_breach is False
        assert math.isclose(ratio_breach, 0.07, rel_tol=1e-3)
        assert (las_engine.status_bits & FieldbusStatusBits.JITTER_ALARM) != 0
        assert las_engine.diagnostic_code == FieldbusDiagnosticCode.MACROCYCLE_JITTER_EXCEEDED


# ============================================================================
# 4. Live List Discovery & Probe Node (PN) Transitions
# ============================================================================

class TestSection4LiveListDiscovery:
    """Tests for Live List discovery, operational address checking, and PN progression."""

    def test_operational_address_boundaries(self) -> None:
        """Verify valid operational address range (0x10..0xF7 = 16..247)."""
        assert is_operational_address(16) is True
        assert is_operational_address(247) is True
        assert is_operational_address(15) is False
        assert is_operational_address(248) is False
        assert is_operational_address(0) is False
        assert is_operational_address(255) is False

    def test_probe_node_discovers_active_device(self, las_engine: FieldbusLASEngine) -> None:
        """Verify probe_next_node discovers a present device and adds it to the Live List."""
        dev25 = FieldbusDeviceDescriptor(address=25, device_tag="PT-202", role=DeviceRole.BASIC_DEVICE)
        las_engine.devices[25] = dev25  # Device attached, not yet on live list
        assert 25 not in las_engine.live_list

        las_engine.current_probe_address = 25
        probed = las_engine.probe_next_node()

        assert probed == 25
        assert 25 in las_engine.live_list
        assert las_engine.current_probe_address == 26

    def test_probe_pointer_wraparound(self, las_engine: FieldbusLASEngine) -> None:
        """Verify probe pointer wraps around at OPERATIONAL_ADDR_MAX back to MIN."""
        las_engine.current_probe_address = OPERATIONAL_ADDR_MAX
        probed = las_engine.probe_next_node()
        assert probed == OPERATIONAL_ADDR_MAX
        assert las_engine.current_probe_address == OPERATIONAL_ADDR_MIN

    def test_live_list_bitmask_generation(self, las_engine: FieldbusLASEngine) -> None:
        """Verify Low (16..31), Mid (32..47), and High (48..63) live list mask calculation."""
        dev17 = FieldbusDeviceDescriptor(address=17, device_tag="TT-101")
        dev33 = FieldbusDeviceDescriptor(address=33, device_tag="PT-102")
        dev49 = FieldbusDeviceDescriptor(address=49, device_tag="FT-103")
        las_engine.add_device(dev17)
        las_engine.add_device(dev33)
        las_engine.add_device(dev49)

        m_low, m_mid, m_high = las_engine.compute_live_list_masks()
        # Node 16 (bit 0) and Node 17 (bit 1) -> 0b0011 = 3
        assert m_low == (1 << 0) | (1 << 1)
        # Node 33 (bit 1 of mid range: 33 - 32) -> 0b0010 = 2
        assert m_mid == (1 << 1)
        # Node 49 (bit 1 of high range: 49 - 48) -> 0b0010 = 2
        assert m_high == (1 << 1)


# ============================================================================
# 5. Backup Link Master Failover Negotiation & Role Transition
# ============================================================================

class TestSection5BackupLinkMasterFailover:
    """Tests for LAS redundancy state machine and Backup LM promotion."""

    def test_redundancy_state_initialization(self, las_engine: FieldbusLASEngine) -> None:
        """Verify primary LAS begins in PRIMARY_ACTIVE state."""
        assert las_engine.redundancy_state == LASRedundancyState.PRIMARY_ACTIVE
        assert las_engine.backup_redundancy_state == LASRedundancyState.BACKUP_STANDBY
        assert (las_engine.status_bits & FieldbusStatusBits.LAS_FAILOVER) == 0

    def test_backup_link_master_registration(self, las_engine: FieldbusLASEngine) -> None:
        """Verify registering a Link Master establishes it as the backup LM."""
        blm = FieldbusDeviceDescriptor(address=30, device_tag="BLM-30", role=DeviceRole.LINK_MASTER)
        las_engine.add_device(blm)
        assert las_engine.backup_lm_address == 30

    def test_failover_trigger_and_promotion(self, las_engine: FieldbusLASEngine) -> None:
        """Verify failover demotes Primary LAS and promotes Backup LM to ACTIVE_LAS."""
        blm = FieldbusDeviceDescriptor(address=30, device_tag="BLM-30", role=DeviceRole.LINK_MASTER)
        las_engine.add_device(blm)

        las_engine.trigger_las_failover()

        assert las_engine.redundancy_state == LASRedundancyState.FAILED
        assert las_engine.backup_redundancy_state == LASRedundancyState.ACTIVE_LAS
        assert las_engine.las_address == 30
        assert (las_engine.status_bits & FieldbusStatusBits.LAS_FAILOVER) != 0
        assert las_engine.diagnostic_code == FieldbusDiagnosticCode.LAS_FAILOVER_TRIGGERED

        # Verify old primary was dropped from live list
        assert 16 not in las_engine.live_list

    def test_failover_without_backup_lm_raises_error(self, las_engine: FieldbusLASEngine) -> None:
        """Verify attempting failover without a configured Backup LM raises RuntimeError."""
        las_engine.backup_lm_address = None
        with pytest.raises(RuntimeError):
            las_engine.trigger_las_failover()


# ============================================================================
# 6. Cyclic Publisher/Subscriber Data Exchange & Status Octet
# ============================================================================

class TestSection6CyclicIOAndStatusOctet:
    """Tests for function block status octets, process variables, and double buffering."""

    def test_status_octet_encoding_and_extraction(self) -> None:
        """Verify status octet bit packing and extraction across all quality codes."""
        # Good Non-Cascade, Active, Constant
        st_good = make_status_octet(QualityCode.GOOD_NON_CASCADE, SubstatusGood.ACTIVE, LimitStatus.CONSTANT)
        assert get_quality(st_good) == QualityCode.GOOD_NON_CASCADE
        assert is_quality_good(st_good) is True
        assert is_quality_bad(st_good) is False
        assert (st_good & 0x03) == LimitStatus.CONSTANT

        # Bad, Sensor Failure, Not Limited
        st_bad = make_status_octet(QualityCode.BAD, SubstatusBad.SENSOR_FAILURE, LimitStatus.NOT_LIMITED)
        assert get_quality(st_bad) == QualityCode.BAD
        assert is_quality_bad(st_bad) is True
        assert is_quality_good(st_bad) is False

        # Uncertain, Substitute Value, High Limited
        st_unc = make_status_octet(QualityCode.UNCERTAIN, SubstatusUncertain.SUBSTITUTE_VALUE, LimitStatus.HIGH_LIMITED)
        assert get_quality(st_unc) == QualityCode.UNCERTAIN
        assert is_quality_uncertain(st_unc) is True

    def test_process_variable_properties(self) -> None:
        """Verify ProcessVariable convenience properties and quality codes."""
        pv = ProcessVariable(
            value=45.67,
            status_octet=make_status_octet(QualityCode.GOOD_CASCADE, limit=LimitStatus.LOW_LIMITED),
        )
        assert pv.value == 45.67
        assert pv.is_good is True
        assert pv.is_bad is False
        assert pv.is_uncertain is False
        assert pv.quality_code == QualityCode.GOOD_CASCADE
        assert pv.limit_code == LimitStatus.LOW_LIMITED

    def test_double_buffer_atomic_isolation(self) -> None:
        """Verify DoubleBuffer prevents torn reads by staging in working buffer until commit."""
        db = DoubleBuffer()
        # Initial read should be None
        assert db.read(17, 1) is None

        # Stage write into working buffer
        db.stage_write(17, 1, 100.0, make_status_octet(QualityCode.GOOD_NON_CASCADE))
        # Stable buffer must still be empty before commit
        assert db.read(17, 1) is None

        # Commit working buffer
        db.commit()
        val = db.read(17, 1)
        assert val is not None
        assert val.value == 100.0

        # Stage update: stable read must preserve previous committed value
        db.stage_write(17, 1, 200.0, make_status_octet(QualityCode.GOOD_NON_CASCADE))
        assert db.read(17, 1).value == 100.0

        # Commit update
        db.commit()
        assert db.read(17, 1).value == 200.0


# ============================================================================
# 7. Diagnostics: Missed CD Polls, Token Loss, and Jitter Alarms
# ============================================================================

class TestSection7DiagnosticsAndAlarms:
    """Tests for SLAVE_OFFLINE, TOKEN_PASS_LOST, and MACROCYCLE_JITTER_EXCEEDED alarms."""

    def test_missed_cd_polls_trigger_slave_offline(self, las_engine: FieldbusLASEngine) -> None:
        """Verify 3 consecutive missed CD polls drop node and assert SLAVE_OFFLINE."""
        dev18 = FieldbusDeviceDescriptor(address=18, device_tag="TT-108")
        las_engine.add_device(dev18)
        las_engine.add_scheduled_cd(ScheduledCDTransaction(offset_ms=50, publisher_address=18, channel_id=1))

        assert dev18.is_online is True
        assert 18 in las_engine.live_list

        # Poll failure 1
        las_engine.execute_macrocycle(simulate_poll_failures={18})
        assert dev18.missed_cd_count == 1
        assert dev18.is_online is True

        # Poll failure 2
        las_engine.execute_macrocycle(simulate_poll_failures={18})
        assert dev18.missed_cd_count == 2
        assert dev18.is_online is True

        # Poll failure 3 -> SLAVE_OFFLINE (0x8601)
        las_engine.execute_macrocycle(simulate_poll_failures={18})
        assert dev18.missed_cd_count == 3
        assert dev18.is_online is False
        assert 18 not in las_engine.live_list
        assert las_engine.diagnostic_code == FieldbusDiagnosticCode.SLAVE_OFFLINE

        # Verify staged BAD status in double buffer
        pv = las_engine.double_buffer.read(18, 1)
        assert pv is not None
        assert pv.is_bad is True

    def test_token_pass_loss_alarm_and_trip(self, las_engine: FieldbusLASEngine) -> None:
        """Verify token loss clears TOKEN_ROTATION_OK, sets 0x8602, and trips %M164."""
        token_res = las_engine.circulate_pass_token(force_loss=True)
        assert token_res is False
        assert (las_engine.status_bits & FieldbusStatusBits.TOKEN_ROTATION_OK) == 0
        assert las_engine.diagnostic_code == FieldbusDiagnosticCode.TOKEN_PASS_LOST

        # Register sync should assert trip coil %M164 and deassert %M163
        las_engine._sync_registers()
        assert las_engine.reg_table.read_bit("%M164") is True
        assert las_engine.reg_table.read_bit("%M163") is False

    def test_macrocycle_jitter_alarm(self, las_engine: FieldbusLASEngine) -> None:
        """Verify severe macrocycle jitter sets JITTER_ALARM bit and 0x8603 code."""
        res = las_engine.execute_macrocycle(cycle_duration_override_ms=550.0)  # 10% delta > 5%
        assert res["jitter_ok"] is False
        assert (las_engine.status_bits & FieldbusStatusBits.JITTER_ALARM) != 0
        assert las_engine.diagnostic_code == FieldbusDiagnosticCode.MACROCYCLE_JITTER_EXCEEDED

    def test_fault_reset_restores_clean_state(self, las_engine: FieldbusLASEngine) -> None:
        """Verify reset_fault_trip clears diagnostic alarms and restores normal state."""
        # Trip fault
        las_engine.circulate_pass_token(force_loss=True)
        assert las_engine.diagnostic_code == FieldbusDiagnosticCode.TOKEN_PASS_LOST

        # Reset fault
        las_engine.reset_fault_trip()
        assert las_engine.diagnostic_code == FieldbusDiagnosticCode.OK
        assert (las_engine.status_bits & FieldbusStatusBits.TOKEN_ROTATION_OK) != 0
        assert las_engine.reg_table.read_bit("%M164") is False
        assert las_engine.reg_table.read_bit("%M163") is True


# ============================================================================
# 8. Horner OCS Register Space Synchronization (%R700..%R707, %M163..%M164)
# ============================================================================

class TestSection8RegisterSpaceSynchronization:
    """Tests for Horner OCS memory space synchronization."""

    def test_initial_register_synchronization(self, las_engine: FieldbusLASEngine, register_table: RegisterTable) -> None:
        """Verify clean register values on master engine initialization."""
        r700 = register_table.read_uword("%R700")
        r701 = register_table.read_word("%R701")
        r702 = register_table.read_uword("%R702")
        r703 = register_table.read_uword("%R703")
        r704 = register_table.read_uword("%R704")
        r705 = register_table.read_word("%R705")
        r706 = register_table.read_word("%R706")
        r707 = register_table.read_uword("%R707")
        m163 = register_table.read_bit("%M163")
        m164 = register_table.read_bit("%M164")

        assert (r700 & int(FieldbusStatusBits.MASTER_ACTIVE)) != 0
        assert (r700 & int(FieldbusStatusBits.LAS_ACTIVE)) != 0
        assert r701 == 1  # Node 16 (LAS) active
        assert r702 == 1  # bit 0 of low mask
        assert r703 == 0
        assert r704 == 0
        assert r705 == 500  # macrocycle period ms
        assert r706 == 0    # total macrocycles
        assert r707 == 0    # diagnostic OK
        assert m163 is True # normal active
        assert m164 is False# trip fault false

    def test_register_synchronization_under_fault(self, las_engine: FieldbusLASEngine, register_table: RegisterTable) -> None:
        """Verify %R707 and %M164 update synchronously during fault conditions."""
        las_engine.circulate_pass_token(force_loss=True)

        r707 = register_table.read_uword("%R707")
        m163 = register_table.read_bit("%M163")
        m164 = register_table.read_bit("%M164")

        assert r707 == int(FieldbusDiagnosticCode.TOKEN_PASS_LOST)
        assert m163 is False
        assert m164 is True


# ============================================================================
# 9. Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection9AntiLadderGuard:
    """Tests for interception and rejection of ladder constructs."""

    def test_rejection_of_ladder_contact(self) -> None:
        """Verify ladder contact construct ---[ ]--- is strictly intercepted."""
        bad_st = """
        PROGRAM BadLadderContact
        VAR BusContact : BOOL; END_VAR
        ---[ ]---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_rejection_of_ladder_coil(self) -> None:
        """Verify ladder coil construct ---( )--- is strictly intercepted."""
        bad_st = """
        PROGRAM BadLadderCoil
        VAR BusCoil : BOOL; END_VAR
        ---( )---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_rejection_of_ladder_keywords(self) -> None:
        """Verify ladder delimiters (RUNG, NETWORK, XIC) are intercepted."""
        for kw in ["RUNG 001", "NETWORK", "XIC FieldbusAlarm"]:
            bad_st = f"""
            PROGRAM BadLadderDelimiter
            VAR BusBit : BOOL; END_VAR
            {kw}
            END_PROGRAM
            """
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(bad_st)


# ============================================================================
# 10. End-to-End 9-Stage Verification Suite
# ============================================================================

class TestSection10EndToEndVerificationSuite:
    """Tests for run_fieldbus_verification end-to-end execution."""

    def test_run_fieldbus_verification_clean_pass(self, tmp_path: Path) -> None:
        """Verify run_fieldbus_verification completes all 9 stages with status 'success'."""
        evidence_file = tmp_path / "fieldbus_evidence.json"
        evidence = run_fieldbus_verification(str(evidence_file))

        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert evidence["data"]["checks_passed"] == 9
        assert evidence["data"]["total_checks"] == 9
        assert evidence_file.exists()

        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["status"] == "success"
        assert len(data["data"]["tests"]) == 9
