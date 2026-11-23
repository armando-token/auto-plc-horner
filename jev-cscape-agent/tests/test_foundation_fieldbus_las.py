"""Comprehensive Unit and Integration Test Suite for Industrial FOUNDATION Fieldbus H1 LAS Engine.

Work Package: W181 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation
   (%R1420..%R1427, %M331..%M332).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: LAS token dispatching (PT, CD, PN, TD) and macrocycle execution schedule.
4. Section 4: Standard FF Function Block execution (AI, AO, PID, DI, DO, Resource Block).
5. Section 5: Status bytes (Good 0x80, Uncertain 0x40, Bad 0x00) and limit flags.
6. Section 6: Process safety trips (0xCE01 macrocycle deadlock, 0xCE02 high jitter, 0xCE03 device dropout, 0xCE04 block fault) and Horner coil assertion (%M331, %M332).
7. Section 7: Horner OCS register space synchronization (%R1420..%R1427, %M331..%M332) with PrivilegeMode.SYSTEM.
8. Section 8: ILogicUnit scan cycle execution and state machine transitions.
9. Section 9: 9-stage verification suite integration test writing evidence JSON.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.foundation_fieldbus_las import (
    BLOCK_EXECUTION_FAULT,
    BLOCK_FAULT,
    BROADCAST_ADDRESS,
    COMMUNICATION_JITTER_HIGH,
    DEFAULT_MACROCYCLE_PERIOD_MS,
    DEFAULT_TOKEN_HOLD_TIME_MS,
    DEVICE_DROPOUT,
    DEVICE_STATION_DROPOUT,
    END_DELIMITER,
    ERR_BLOCK_FAULT,
    ERR_DEVICE_DROPOUT,
    ERR_HIGH_JITTER,
    ERR_MACROCYCLE_DEADLOCK,
    FF_ERR_BLOCK_EXECUTION_FAULT,
    FF_ERR_BLOCK_FAULT,
    FF_ERR_COMMUNICATION_JITTER_HIGH,
    FF_ERR_DEVICE_DROPOUT,
    FF_ERR_DEVICE_STATION_DROPOUT,
    FF_ERR_HIGH_JITTER,
    FF_ERR_LAS_MACROCYCLE_DEADLOCK,
    FF_ERR_MACROCYCLE_DEADLOCK,
    FF_H1_FUNCTION_BLOCK_BRIDGE_SYNC_POU,
    FF_H1_LAS_SYNC_POU,
    FF_LAS_SYNC_POU,
    FF_LIMIT_CONSTANT,
    FF_LIMIT_HIGH,
    FF_LIMIT_LOW,
    FF_LIMIT_NOT_LIMITED,
    FF_QUALITY_BAD,
    FF_QUALITY_GOOD,
    FF_QUALITY_GOOD_CASCADE,
    FF_QUALITY_UNCERTAIN,
    FF_SUBSTATUS_BAD_CONFIG_ERROR,
    FF_SUBSTATUS_BAD_DEVICE_FAILURE,
    FF_SUBSTATUS_BAD_NON_SPECIFIC,
    FF_SUBSTATUS_BAD_NOT_CONNECTED,
    FF_SUBSTATUS_BAD_OUT_OF_SERVICE,
    FF_SUBSTATUS_BAD_SENSOR_FAILURE,
    FF_SUBSTATUS_GOOD_ACTIVE_ADVISORY_ALARM,
    FF_SUBSTATUS_GOOD_ACTIVE_CRITICAL_ALARM,
    FF_SUBSTATUS_GOOD_CASCADE,
    FF_SUBSTATUS_GOOD_NON_SPECIFIC,
    FF_SUBSTATUS_UNCERTAIN_EU_EXCEEDED,
    FF_SUBSTATUS_UNCERTAIN_INITIAL_VALUE,
    FF_SUBSTATUS_UNCERTAIN_LAST_USABLE,
    FF_SUBSTATUS_UNCERTAIN_NON_SPECIFIC,
    FF_SUBSTATUS_UNCERTAIN_SENSOR_INACCURATE,
    FIELDBUS_BAUD_RATE_BPS,
    FIELDBUS_BIT_TIME_US,
    FIELDBUS_LAS_BRIDGE_SYNC_POU,
    FIELDBUS_LAS_POU,
    FOUNDATION_FIELDBUS_LAS_SYNC_POU,
    FOUNDATION_FIELDBUS_POU,
    FOUNDATION_LAS_POU,
    HIGH_JITTER,
    LAS_MACROCYCLE_DEADLOCK,
    MACROCYCLE_DEADLOCK,
    MACROCYCLE_DEADLOCK_TIMEOUT_MS,
    MAX_BUS_JITTER_US,
    NOMINAL_BUS_JITTER_US,
    NOMINAL_LATENCY_SCALED,
    NOMINAL_MACROCYCLE_LATENCY_MS,
    OPERATIONAL_ADDR_MAX,
    OPERATIONAL_ADDR_MIN,
    PREAMBLE_OCTET,
    PURE_ST_POU,
    START_DELIMITER,
    AnalogInputBlock,
    AnalogOutputBlock,
    BlockFaultError,
    BlockMode,
    DeviceDropoutError,
    DiscreteInputBlock,
    DiscreteOutputBlock,
    FFBlockMode,
    FFDiagnosticCode,
    FFEngineState,
    FFFrameType,
    FFLasEngine,
    FFLasStateBits,
    FFMacrocycleDeadlockError,
    FFToken,
    FfBlockExecutionFaultError,
    FfCommunicationJitterHighError,
    FfDeviceDescriptor,
    FfDeviceStationDropoutError,
    FfH1DlpduType,
    FfLasDiagnosticCode,
    FfLasGatewayState,
    FfLasMacrocycleDeadlockError,
    FfLasStateBits,
    FieldbusH1Frame,
    FoundationFieldbusError,
    FoundationFieldbusLas,
    FoundationFieldbusLasEngine,
    FoundationFieldbusLasError,
    FunctionBlockMode,
    HighJitterError,
    LasEngineState,
    LasStateBits,
    LimitStatus,
    MacrocycleDeadlockError,
    PIDBlock,
    QualityCode,
    ResourceBlock,
    ScheduledCDTransaction,
    SubstatusBad,
    SubstatusGood,
    SubstatusUncertain,
    TransducerBlock,
    compute_crc16_ccitt,
    decode_ff_status,
    encode_ff_status,
    evaluate_ff_status_summary,
    get_limit,
    get_limit_flag,
    get_quality,
    get_substatus,
    is_bad_quality,
    is_good_quality,
    is_quality_bad,
    is_quality_good,
    is_quality_uncertain,
    is_uncertain_quality,
    make_status_byte,
    run_fieldbus_las_verification,
    run_foundation_fieldbus_las_verification,
    safe_write_bit,
    safe_write_uword,
    safe_write_word,
    set_limit_flag,
    verify_fieldbus_las_pure_st,
    verify_foundation_fieldbus_las_pure_st,
)


@pytest.fixture
def clean_register_table() -> RegisterTable:
    """Fixture providing clean Horner OCS RegisterTable."""
    return RegisterTable()


@pytest.fixture
def las_engine(clean_register_table: RegisterTable) -> FoundationFieldbusLasEngine:
    """Fixture providing fresh FoundationFieldbusLasEngine bound to clean RegisterTable."""
    return FoundationFieldbusLasEngine(register_table=clean_register_table)


# ============================================================================
# Section 1: Pure ST POU AST Parsing & Register Bindings (%R1420..%R1427, %M331..%M332)
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for Pure Structured Text POU compliance and register bindings."""

    EXPECTED_REGISTERS = {
        "%R1420", "%R1421", "%R1422", "%R1423",
        "%R1424", "%R1425", "%R1426", "%R1427",
        "%M331", "%M332",
    }

    def test_verify_foundation_fieldbus_las_pure_st_helper(self) -> None:
        """Verify built-in pure ST validation helpers return True."""
        assert verify_foundation_fieldbus_las_pure_st() is True
        assert verify_fieldbus_las_pure_st() is True

    def test_pure_st_pou_ast_parsing_and_variables(self) -> None:
        """Parse FOUNDATION_FIELDBUS_LAS_SYNC_POU with STParser and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(FOUNDATION_FIELDBUS_LAS_SYNC_POU)
        assert pou is not None
        assert pou.name == "FoundationFieldbusLasSync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "ActiveDevicesCount",
            "ScheduledBlocksCount",
            "MacrocycleLatencyMsScaled",
            "BusJitterMicroseconds",
            "DroppedTokenCounter",
            "FfLasStateWord",
            "MacrocyclePeriodMs",
            "DiagnosticStatusCode",
            "FfLasPermissive",
            "FfLasFaultTrip",
            "LasHealthy",
        }
        assert expected_vars.issubset(var_names)
        assert set(pou.bound_registers) == self.EXPECTED_REGISTERS

    def test_alias_pou_ast_parsing(self) -> None:
        """Parse FF_H1_FUNCTION_BLOCK_BRIDGE_SYNC_POU alias with STParser."""
        parser = STParser()
        pou = parser.parse_pou(FF_H1_FUNCTION_BLOCK_BRIDGE_SYNC_POU)
        assert pou is not None
        assert pou.name == "FfH1FunctionBlockBridgeSync"
        assert pou.pou_type == POUType.PROGRAM
        assert set(pou.bound_registers) == self.EXPECTED_REGISTERS

    def test_st_parser_validate_code(self) -> None:
        """Verify STParser.validate_code succeeds on valid POU source."""
        res = STParser.validate_code(FOUNDATION_FIELDBUS_LAS_SYNC_POU)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify all POU aliases pass SecurityGuard assertion cleanly."""
        SecurityGuard.assert_pure_st_content(FOUNDATION_FIELDBUS_LAS_SYNC_POU)
        SecurityGuard.assert_pure_st_content(FF_H1_FUNCTION_BLOCK_BRIDGE_SYNC_POU)
        SecurityGuard.assert_pure_st_content(PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(FOUNDATION_FIELDBUS_POU)
        SecurityGuard.assert_pure_st_content(FF_H1_LAS_SYNC_POU)
        SecurityGuard.assert_pure_st_content(FIELDBUS_LAS_BRIDGE_SYNC_POU)
        SecurityGuard.assert_pure_st_content(FF_LAS_SYNC_POU)
        SecurityGuard.assert_pure_st_content(FIELDBUS_LAS_POU)
        SecurityGuard.assert_pure_st_content(FOUNDATION_LAS_POU)


# ============================================================================
# Section 2: Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Tests verifying ladder logic constructs are strictly rejected."""

    def test_ladder_contacts_rejected(self) -> None:
        """Reject ASCII ladder contacts ---[ ]--- and inverted ---[/]---."""
        bad_st_1 = "PROGRAM BadContacts\nVAR X: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)
        res1 = STParser.validate_code(bad_st_1)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_2 = "PROGRAM BadContactsInv\nVAR X: BOOL; END_VAR\n---[/]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)
        res2 = STParser.validate_code(bad_st_2)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "ERR_LADDER_FORBIDDEN"

    def test_ladder_coils_rejected(self) -> None:
        """Reject ASCII ladder coils ---( )---, set ---(S)---, and reset ---(R)---."""
        bad_st_1 = "PROGRAM BadCoils\nVAR Y: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)
        res1 = STParser.validate_code(bad_st_1)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_2 = "PROGRAM BadCoilsSet\nVAR Y: BOOL; END_VAR\n---(S)---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)
        res2 = STParser.validate_code(bad_st_2)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_3 = "PROGRAM BadCoilsReset\nVAR Y: BOOL; END_VAR\n---(R)---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_3)
        res3 = STParser.validate_code(bad_st_3)
        assert res3.status == AgentStatus.FAILED
        assert res3.error_code == "ERR_LADDER_FORBIDDEN"

    def test_ladder_mnemonics_rejected(self) -> None:
        """Reject ladder mnemonics XIC, XIO, OTE, OTL, OTU, and RUNG/NETWORK blocks."""
        bad_st_1 = "PROGRAM BadMnemonics\nVAR Z: BOOL; END_VAR\nRUNG 1: XIC %M1 OTE %M2 END_RUNG\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_1)
        res1 = STParser.validate_code(bad_st_1)
        assert res1.status == AgentStatus.FAILED
        assert res1.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_2 = "PROGRAM BadNetwork\nVAR W: BOOL; END_VAR\nNETWORK 1\nOTL %M331\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_2)
        res2 = STParser.validate_code(bad_st_2)
        assert res2.status == AgentStatus.FAILED
        assert res2.error_code == "ERR_LADDER_FORBIDDEN"

        bad_st_3 = "PROGRAM BadXioOtu\nVAR A: BOOL; END_VAR\nXIO %M10 OTU %M20\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st_3)
        res3 = STParser.validate_code(bad_st_3)
        assert res3.status == AgentStatus.FAILED
        assert res3.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 3: LAS Token Dispatching & Macrocycle Execution Schedule
# ============================================================================

class TestSection3LasTokenDispatchingAndSchedule:
    """Tests for LAS Token Dispatching (PT, CD, PN, TD) and macrocycle execution schedule."""

    def test_token_types_enumeration_and_constants(self) -> None:
        """Verify FfH1DlpduType token enum values and protocol parameters."""
        assert FfH1DlpduType.COMPEL_DATA == 0x01
        assert FfH1DlpduType.PASS_TOKEN == 0x02
        assert FfH1DlpduType.PROBE_NODE == 0x03
        assert FfH1DlpduType.PROBE_RESPONSE == 0x04
        assert FfH1DlpduType.TIME_DISTRIBUTION == 0x05
        assert FfH1DlpduType.DATA_RESPONSE == 0x06
        assert FfH1DlpduType.RETURN_TOKEN == 0x07

        assert FIELDBUS_BAUD_RATE_BPS == 31250
        assert FIELDBUS_BIT_TIME_US == 32.0
        assert PREAMBLE_OCTET == 0x55
        assert START_DELIMITER == 0x57
        assert END_DELIMITER == 0x71
        assert BROADCAST_ADDRESS == 0xFF
        assert OPERATIONAL_ADDR_MIN == 0x10
        assert OPERATIONAL_ADDR_MAX == 0xF7
        assert DEFAULT_MACROCYCLE_PERIOD_MS == 100
        assert DEFAULT_TOKEN_HOLD_TIME_MS == 20.0

    def test_crc16_ccitt_determinism(self) -> None:
        """Verify standard IEC 61158-2 CRC-16-CCITT checksum computation."""
        test_data = b"123456789"
        crc = compute_crc16_ccitt(test_data)
        assert crc == 0x29B1

    def test_wire_framing_encode_decode_roundtrip(self) -> None:
        """Verify frame serialization, framing delimiters, and roundtrip decoding."""
        payload = b"\x01\x02\x03\x04"
        frame = FieldbusH1Frame(
            frame_type=FfH1DlpduType.COMPEL_DATA,
            dest_address=0x11,
            src_address=0x10,
            payload=payload,
        )
        raw = frame.encode()
        assert raw[0] == PREAMBLE_OCTET
        assert raw[1] == START_DELIMITER
        assert raw[-1] == END_DELIMITER

        decoded = FieldbusH1Frame.decode(raw)
        assert decoded.frame_type == FfH1DlpduType.COMPEL_DATA
        assert decoded.dest_address == 0x11
        assert decoded.src_address == 0x10
        assert decoded.payload == payload

    def test_frame_decode_corrupted_crc_raises(self) -> None:
        """Corrupted CRC bytes raise ValueError during frame decoding."""
        frame = FieldbusH1Frame(
            frame_type=FfH1DlpduType.PASS_TOKEN,
            dest_address=0x15,
            src_address=0x10,
            payload=b"\x00\x14",
        )
        raw = bytearray(frame.encode())
        raw[-2] ^= 0xFF
        with pytest.raises(ValueError, match="CRC-16 mismatch"):
            FieldbusH1Frame.decode(bytes(raw))

    def test_time_distribution_broadcast(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify Time Distribution frame broadcasting."""
        td_frame = las_engine.distribute_time(timestamp_ns=1700000000123456789)
        assert td_frame.frame_type == FfH1DlpduType.TIME_DISTRIBUTION
        assert td_frame.dest_address == BROADCAST_ADDRESS
        assert td_frame.src_address == 0x10
        assert len(td_frame.payload) == 8

    def test_pass_token_circulation(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify Pass Token circulation across live list."""
        assert las_engine.circulate_pass_token() is True
        assert las_engine.circulate_pass_token(force_drop=True) is False
        assert las_engine.dropped_token_counter == 1

    def test_probe_node_round_robin(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify round-robin address probing across 0x10..0xF7."""
        las_engine.current_probe_address = OPERATIONAL_ADDR_MIN
        p1 = las_engine.probe_next_node()
        assert p1 == OPERATIONAL_ADDR_MIN
        assert las_engine.current_probe_address == OPERATIONAL_ADDR_MIN + 1

        las_engine.current_probe_address = OPERATIONAL_ADDR_MAX
        p_last = las_engine.probe_next_node()
        assert p_last == OPERATIONAL_ADDR_MAX
        assert las_engine.current_probe_address == OPERATIONAL_ADDR_MIN

    def test_macrocycle_schedule_execution_success(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify 100ms macrocycle execution advances cycle count and dispatches scheduled CD tokens."""
        assert las_engine.active_devices_count == 12
        assert len(las_engine.scheduled_cd_list) == 24

        res = las_engine.execute_macrocycle(cycle_duration_override_ms=100.0)
        assert res["status"] == "success"
        assert res["cycle"] == 1
        assert res["scheduled_success"] == 24
        assert las_engine.state == FfLasGatewayState.MACROCYCLE_SCHEDULED
        assert las_engine.permissive is True
        assert las_engine.fault_trip is False


# ============================================================================
# Section 4: Standard FF Function Block Execution
# ============================================================================

class TestSection4FunctionBlockExecution:
    """Tests for Standard FF Function Blocks (AI, AO, PID, DI, DO, Resource Block, Transducer Block)."""

    def test_transducer_block_calibration(self) -> None:
        """Verify TransducerBlock linear calibration and primary value conversion."""
        tb = TransducerBlock(
            tag="TB_101",
            channel_id=1,
            sensor_type="4-20mA_ANALOG",
            raw_value=12.0,
            cal_point_lo=4.0,
            cal_point_hi=20.0,
            eu_range=(0.0, 100.0),
        )
        val, stat = tb.read_transducer()
        assert math.isclose(val, 50.0, rel_tol=1e-3)
        assert is_quality_good(stat)

        raw, _ = tb.write_transducer(75.0)
        assert math.isclose(raw, 16.0, rel_tol=1e-3)

        tb.calibrate(3.8, 20.2)
        assert tb.cal_point_lo == 3.8
        assert tb.cal_point_hi == 20.2

    def test_resource_block_health_and_alarms(self) -> None:
        """Verify ResourceBlock status reporting, OOS mode, and alarm detection."""
        rb = ResourceBlock(tag="RB_101", device_address=0x11, mode=FunctionBlockMode.AUTO)
        assert is_quality_good(rb.execute())

        rb.mode = FunctionBlockMode.OOS
        assert is_quality_bad(rb.execute())
        assert get_substatus(rb.execute()) == SubstatusBad.OUT_OF_SERVICE

        rb.mode = FunctionBlockMode.AUTO
        rb.alarms.append("HARDWARE_EEPROM_CRC")
        assert is_quality_bad(rb.execute())
        assert get_substatus(rb.execute()) == SubstatusBad.DEVICE_FAILURE

    def test_analog_input_block_filtering_and_alarms(self) -> None:
        """Verify AI block scaling, first-order lag filter, and alarm limit clamps."""
        tb = TransducerBlock(
            tag="TB_AI",
            channel_id=1,
            raw_value=12.0,
            cal_point_lo=4.0,
            cal_point_hi=20.0,
            eu_range=(0.0, 100.0),
        )
        ai = AnalogInputBlock(tag="AI_101", channel=1, transducer=tb, scale_in=(4.0, 20.0), scale_out=(0.0, 100.0))
        out_v, stat = ai.execute(dt=0.01)
        assert math.isclose(out_v, 50.0, rel_tol=1e-3)
        assert is_quality_good(stat)
        assert ai.active_alarm is None

        # Drive to HI_HI alarm (> 95.0)
        tb.raw_value = 19.5
        out_hi, stat_hi = ai.execute(dt=0.01)
        assert out_hi >= 95.0
        assert ai.active_alarm == "HI_HI"
        assert get_substatus(stat_hi) == SubstatusGood.ACTIVE_CRITICAL_ALARM
        assert get_limit(stat_hi) == LimitStatus.HIGH_LIMITED

    def test_pid_and_analog_output_closed_loop(self) -> None:
        """Verify closed-loop AI -> PID -> AO cascade connection."""
        tb_sensor = TransducerBlock(tag="TB_SENS", channel_id=1, raw_value=12.0, cal_point_lo=4.0, cal_point_hi=20.0, eu_range=(0.0, 100.0))
        ai = AnalogInputBlock(tag="AI_LOOP", channel=1, transducer=tb_sensor, scale_in=(4.0, 20.0), scale_out=(0.0, 100.0))
        ai_val, ai_stat = ai.execute(dt=0.01)

        pid = PIDBlock(tag="PID_LOOP", sp=50.0, in_val=ai_val, in_status=ai_stat, gain=1.5, reset_time_s=10.0)
        pid_val, pid_stat = pid.execute(dt=0.01)

        tb_valve = TransducerBlock(tag="TB_VALVE", channel_id=2, raw_value=50.0, cal_point_lo=0.0, cal_point_hi=100.0, eu_range=(0.0, 100.0))
        ao = AnalogOutputBlock(tag="AO_LOOP", channel=2, transducer=tb_valve, mode=FunctionBlockMode.CAS, cas_in=pid_val, cas_in_status=pid_stat)
        ao_val, ao_stat = ao.execute(dt=0.01)

        assert math.isclose(ao_val, pid_val, rel_tol=1e-3)
        assert is_quality_good(ao_stat)
        assert math.isclose(ao.readback, pid_val, rel_tol=1e-3)

    def test_discrete_input_and_output_blocks(self) -> None:
        """Verify DI and DO block execution and inversion logic."""
        tb_di = TransducerBlock(tag="TB_DI", channel_id=1, sensor_type="DISCRETE", raw_value=1.0, cal_point_lo=0.0, cal_point_hi=1.0, eu_range=(0.0, 1.0))
        di = DiscreteInputBlock(tag="DI_101", channel=1, transducer=tb_di, invert=False)
        val, stat = di.execute()
        assert val is True
        assert is_quality_good(stat)

        di.invert = True
        val_inv, _ = di.execute()
        assert val_inv is False

        tb_do = TransducerBlock(tag="TB_DO", channel_id=2, sensor_type="DISCRETE", raw_value=0.0, cal_point_lo=0.0, cal_point_hi=1.0, eu_range=(0.0, 1.0))
        do = DiscreteOutputBlock(tag="DO_101", channel=2, transducer=tb_do, sp_d=True)
        do_val, do_stat = do.execute()
        assert do_val is True
        assert do.readback_d is True
        assert is_quality_good(do_stat)


# ============================================================================
# Section 5: Status Bytes Quality Octet & Limit Flags Evaluation
# ============================================================================

class TestSection5StatusBytesQualityAndLimitFlags:
    """Tests for FF-891 8-bit status octet encoding (Good 0x80/0xC0, Uncertain 0x40, Bad 0x00) and limit flags."""

    def test_status_byte_encoding_and_extraction(self) -> None:
        """Verify status byte encoding and field decomposition."""
        b = make_status_byte(QualityCode.GOOD_NON_CASCADE, SubstatusGood.ACTIVE_ADVISORY_ALARM, LimitStatus.HIGH_LIMITED)
        assert get_quality(b) == QualityCode.GOOD_NON_CASCADE
        assert get_substatus(b) == SubstatusGood.ACTIVE_ADVISORY_ALARM
        assert get_limit(b) == LimitStatus.HIGH_LIMITED
        assert is_quality_good(b) is True
        assert is_good_quality(b) is True
        assert is_quality_uncertain(b) is False
        assert is_quality_bad(b) is False

    def test_uncertain_and_bad_quality_helpers(self) -> None:
        """Verify is_quality_uncertain and is_quality_bad."""
        unc = make_status_byte(QualityCode.UNCERTAIN, SubstatusUncertain.EU_EXCEEDED, LimitStatus.NOT_LIMITED)
        assert is_quality_uncertain(unc) is True
        assert is_uncertain_quality(unc) is True
        assert is_quality_good(unc) is False

        bad = make_status_byte(QualityCode.BAD, SubstatusBad.DEVICE_FAILURE, LimitStatus.CONSTANT)
        assert is_quality_bad(bad) is True
        assert is_bad_quality(bad) is True
        assert is_quality_good(bad) is False

    def test_limit_flags_extraction_and_encoding(self) -> None:
        """Verify 2-bit limit flags (Bits 1..0): Not Limited, Low, High, Constant."""
        assert LimitStatus.NOT_LIMITED == 0x00
        assert LimitStatus.LOW_LIMITED == 0x01
        assert LimitStatus.HIGH_LIMITED == 0x02
        assert LimitStatus.CONSTANT == 0x03

        st = make_status_byte(QualityCode.GOOD_NON_CASCADE, SubstatusGood.NON_SPECIFIC, LimitStatus.NOT_LIMITED)
        assert get_limit(st) == LimitStatus.NOT_LIMITED
        assert get_limit_flag(st) == FF_LIMIT_NOT_LIMITED

        st_low = set_limit_flag(st, FF_LIMIT_LOW)
        assert get_limit(st_low) == LimitStatus.LOW_LIMITED

        st_high = set_limit_flag(st, FF_LIMIT_HIGH)
        assert get_limit(st_high) == LimitStatus.HIGH_LIMITED

        st_const = set_limit_flag(st, FF_LIMIT_CONSTANT)
        assert get_limit(st_const) == LimitStatus.CONSTANT

    def test_encode_decode_ff_status_roundtrip(self) -> None:
        """Verify round-trip encoding and decoding of FF status octets."""
        encoded = encode_ff_status(
            quality=FF_QUALITY_GOOD,
            substatus=FF_SUBSTATUS_GOOD_ACTIVE_ADVISORY_ALARM,
            limit=FF_LIMIT_HIGH,
        )
        assert encoded == (0x80 | 0x08 | 0x02)

        dec = decode_ff_status(encoded)
        assert dec["raw_status"] == (0x80 | 0x08 | 0x02)
        assert dec["quality"] == "Good"
        assert dec["limit"] == "HighLimited"
        assert dec["is_good"] is True
        assert dec["is_uncertain"] is False
        assert dec["is_bad"] is False

    def test_evaluate_ff_status_summary(self) -> None:
        """Verify composite status evaluation across multiple function block outputs."""
        assert evaluate_ff_status_summary([]) == QualityCode.GOOD_NON_CASCADE
        assert evaluate_ff_status_summary([0x80, 0x84, 0xC0]) == QualityCode.GOOD_NON_CASCADE
        assert evaluate_ff_status_summary([0x80, 0x44, 0x84]) == QualityCode.UNCERTAIN
        assert evaluate_ff_status_summary([0x80, 0x44, 0x0C]) == QualityCode.BAD


# ============================================================================
# Section 6: Process Safety Trips & Horner Coil Assertion (%M331, %M332)
# ============================================================================

class TestSection6ProcessSafetyTripsAndCoils:
    """Tests for Process Safety Interlocks (0xCE01..0xCE04) and Horner coil assertion (%M331, %M332)."""

    def test_trip_ce01_macrocycle_deadlock(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Trip 0xCE01: Macrocycle overrun > 200ms triggers 0xCE01, sets %M332, clears %M331, increments %R1424."""
        rt = las_engine.reg_table
        init_dropped = las_engine.dropped_token_counter

        res = las_engine.execute_macrocycle(cycle_duration_override_ms=210.0)
        assert res["status"] == "fault"
        assert res["diagnostic"] == 0xCE01
        assert las_engine.diagnostic_code == FfLasDiagnosticCode.FF_ERR_LAS_MACROCYCLE_DEADLOCK
        assert rt.read_uword("%R1427") == 0xCE01
        assert rt.read_bit("%M331") is False
        assert rt.read_bit("%M332") is True
        assert rt.read_word("%R1424") == init_dropped + 1
        assert las_engine.state == FfLasGatewayState.LAS_FAULT

    def test_trip_ce02_communication_jitter_high(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Trip 0xCE02: Bus jitter > 5000us triggers 0xCE02, sets %M332, clears %M331."""
        rt = las_engine.reg_table
        res = las_engine.execute_macrocycle(jitter_override_us=5500)
        assert res["status"] == "fault"
        assert res["diagnostic"] == 0xCE02
        assert las_engine.diagnostic_code == FfLasDiagnosticCode.FF_ERR_COMMUNICATION_JITTER_HIGH
        assert rt.read_uword("%R1427") == 0xCE02
        assert rt.read_bit("%M331") is False
        assert rt.read_bit("%M332") is True

    def test_trip_ce03_device_station_dropout(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Trip 0xCE03: Monitored station dropping off Live List after 3 missed polls triggers 0xCE03."""
        rt = las_engine.reg_table
        las_engine.execute_macrocycle(force_dropout_station=0x11)
        las_engine.execute_macrocycle(force_dropout_station=0x11)
        res = las_engine.execute_macrocycle(force_dropout_station=0x11)
        assert res["status"] == "fault"
        assert res["diagnostic"] == 0xCE03
        assert las_engine.diagnostic_code == FfLasDiagnosticCode.FF_ERR_DEVICE_STATION_DROPOUT
        assert rt.read_uword("%R1427") == 0xCE03
        assert rt.read_bit("%M331") is False
        assert rt.read_bit("%M332") is True
        assert 0x11 not in las_engine.live_list

    def test_trip_ce04_block_execution_fault(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Trip 0xCE04: Function Block BAD execution status triggers 0xCE04."""
        rt = las_engine.reg_table
        res = las_engine.execute_macrocycle(force_block_fault=True)
        assert res["status"] == "fault"
        assert res["diagnostic"] == 0xCE04
        assert las_engine.diagnostic_code == FfLasDiagnosticCode.FF_ERR_BLOCK_EXECUTION_FAULT
        assert rt.read_uword("%R1427") == 0xCE04
        assert rt.read_bit("%M331") is False
        assert rt.read_bit("%M332") is True

    def test_simulate_helper_methods(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify simulate_* helper methods trip faults deterministically."""
        rt = las_engine.reg_table

        # Deadlock
        las_engine.simulate_macrocycle_deadlock()
        assert las_engine.diagnostic_code == 0xCE01
        assert rt.read_bit("%M331") is False
        assert rt.read_bit("%M332") is True

        # Jitter
        las_engine.reset_fault(force=True)
        las_engine.simulate_high_jitter(jitter_us=6000)
        assert las_engine.diagnostic_code == 0xCE02

        # Dropout
        las_engine.reset_fault(force=True)
        las_engine.simulate_device_dropout(device_address=0x12)
        assert las_engine.diagnostic_code == 0xCE03

        # Block fault
        las_engine.reset_fault(force=True)
        las_engine.simulate_block_fault("AI_PT101_A")
        assert las_engine.diagnostic_code == 0xCE04

    def test_safety_latch_persists_across_multiple_scans(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify safety trip remains latched across subsequent scan cycles."""
        las_engine.simulate_macrocycle_deadlock()
        assert las_engine.fault_trip is True

        for _ in range(5):
            las_engine.scan_step(dt=0.010)
            assert las_engine.fault_trip is True
            assert las_engine.permissive is False
            assert las_engine.reg_table.read_bit("%M332") is True
            assert las_engine.reg_table.read_bit("%M331") is False

    def test_operator_manual_reset_handshake_restores_permissive(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify reset_fault restores permissive coil %M331 and clears %M332."""
        las_engine.simulate_macrocycle_deadlock()
        assert las_engine.fault_trip is True

        res = las_engine.reset_fault(force=True)

        assert res.status == AgentStatus.SUCCESS
        assert las_engine.fault_trip is False
        assert las_engine.permissive is True
        assert las_engine.diagnostic_code == FfLasDiagnosticCode.OK
        assert las_engine.reg_table.read_uword("%R1427") == 0x0000
        assert las_engine.reg_table.read_bit("%M331") is True
        assert las_engine.reg_table.read_bit("%M332") is False


# ============================================================================
# Section 7: Horner OCS Register Space Synchronization & PrivilegeMode.SYSTEM
# ============================================================================

class TestSection7RegisterSpaceSynchronization:
    """Tests for %R1420..%R1427 and %M331..%M332 Horner register bindings with PrivilegeMode.SYSTEM."""

    def test_register_map_addresses_and_privilege_mode(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify %R1420..%R1427 and %M331..%M332 are properly updated with SYSTEM privilege."""
        rt = las_engine.reg_table
        las_engine.sync_to_registers()

        assert rt.read_word("%R1420") == 12      # ActiveDevicesCount
        assert rt.read_word("%R1421") == 24      # ScheduledBlocksCount
        assert rt.read_word("%R1422") == 120     # MacrocycleLatencyMsScaled (12.0 ms)
        assert rt.read_word("%R1423") == 1450    # BusJitterMicroseconds
        assert rt.read_word("%R1424") == 0       # DroppedTokenCounter
        assert rt.read_word("%R1426") == 100     # MacrocyclePeriodMs
        assert rt.read_uword("%R1427") == 0x0000 # DiagnosticStatusCode
        assert rt.read_bit("%M331") is True      # FfLasPermissive
        assert rt.read_bit("%M332") is False     # FfLasFaultTrip

    def test_system_privilege_mode_enforced(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify safe write helpers use PrivilegeMode.SYSTEM."""
        rt = las_engine.reg_table
        safe_write_word(rt, "%R1422", 150)
        safe_write_uword(rt, "%R1427", 0x0000)
        safe_write_bit(rt, "%M331", True)

        assert rt.read_word("%R1422") == 150
        assert rt.read_uword("%R1427") == 0x0000
        assert rt.read_bit("%M331") is True

    def test_state_word_bitmask_flags(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify %R1425 state word bitmask flags."""
        sw = las_engine.compute_state_word()
        assert (sw & int(FfLasStateBits.LAS_ACTIVE)) != 0
        assert (sw & int(FfLasStateBits.PERMISSIVE)) != 0
        assert (sw & int(FfLasStateBits.LIVE_LIST_STABLE)) != 0
        assert (sw & int(FfLasStateBits.FAULT_TRIP)) == 0


# ============================================================================
# Section 8: ILogicUnit Scan Cycle Execution and State Machine Transitions
# ============================================================================

class TestSection8ILogicUnitScanCycleAndStateMachine:
    """Tests verifying simulation engine ILogicUnit interface and state transitions."""

    def test_ilogicunit_interface_compliance(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify ILogicUnit contract properties and methods."""
        assert las_engine.name == "foundation_fieldbus_las"
        assert las_engine.priority == 93
        assert las_engine.is_enabled is True

        rt = las_engine.reg_table
        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=100.0,
            get_register=rt.read_register,
            set_register=lambda a, v: rt.write_register(a, v, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda k, d=None: d,
            set_variable=lambda k, v: None,
            record_fault=lambda f: None,
        )
        las_engine.execute(ctx)
        assert las_engine.elapsed_simulation_ms >= 10.0

    def test_ilogicunit_clock_advancement(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify scan_step advances internal simulation clock."""
        t0 = las_engine.elapsed_simulation_ms
        las_engine.scan_step(dt=0.010)
        assert las_engine.elapsed_simulation_ms == pytest.approx(t0 + 10.0, rel=1e-3)

    def test_ilogicunit_reset_lifecycle(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify reset restores engine to healthy state."""
        las_engine.simulate_macrocycle_deadlock()
        assert las_engine.fault_trip is True

        las_engine.reset()
        assert las_engine.fault_trip is False
        assert las_engine.permissive is True
        assert las_engine.diagnostic_code == FfLasDiagnosticCode.OK

    def test_state_machine_transitions(self, las_engine: FoundationFieldbusLasEngine) -> None:
        """Verify state transitions across MACROCYCLE_SCHEDULED, PASSING_TOKEN, and FAULT."""
        las_engine.execute_macrocycle(cycle_duration_override_ms=100.0)
        assert las_engine.state == FfLasGatewayState.MACROCYCLE_SCHEDULED

        las_engine.simulate_macrocycle_deadlock()
        assert las_engine.state == FfLasGatewayState.LAS_FAULT

        las_engine.reset_fault(force=True)
        assert las_engine.state == FfLasGatewayState.MACROCYCLE_SCHEDULED


# ============================================================================
# Section 9: 9-Stage Verification Suite Integration Test Writing Evidence JSON
# ============================================================================

class TestSection9VerificationSuiteIntegration:
    """Tests executing the 9-stage verification suite and checking evidence output."""

    def test_run_foundation_fieldbus_las_verification_suite(self) -> None:
        """Execute 9-stage verification suite, assert all pass, and verify evidence JSON file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ev_file = Path(tmpdir) / "evidence.json"
            result = run_foundation_fieldbus_las_verification(output_path=ev_file)

            assert result["status"] == "success"
            assert result["error_code"] is None
            assert result["data"]["checks_passed"] == 9
            assert result["data"]["total_checks"] == 9
            assert ev_file.exists()

            with open(ev_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
            assert saved["status"] == "success"
            assert saved["data"]["work_package"] == "W181"
            assert saved["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
            assert saved["data"]["register_map"]["analog_registers"] == "%R1420..%R1427"
            assert saved["data"]["register_map"]["discrete_coils"] == "%M331..%M332"
            assert len(saved["data"]["tests"]) == 9
            assert all(t["passed"] for t in saved["data"]["tests"])
