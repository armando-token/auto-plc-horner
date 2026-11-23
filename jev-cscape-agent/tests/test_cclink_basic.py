"""Unit and Integration Test Suite for CC-Link IE Field Basic Protocol Engine.

Work Package: W166 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation
   (%R1270..%R1277, %M296..%M297).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: Frame encoding, serialization, CRC-16-CCITT checksum validation, and truncation rejection.
4. Section 4: Link devices cyclic exchange: RX, RY, RWw, RWr bit/word manipulation and atomic double-buffering.
5. Section 5: Slave station diagnostic state machine progression
   (DISCONNECTED -> LINK_SCAN_WAIT -> CYCLIC_INITIALIZING -> CYCLIC_OPERATION).
6. Section 6: Group cycle time tracking & nominal timing surveillance (%R1270, scaled x10 ms).
7. Section 7: Process safety trips and Horner interlock coil assertions:
   - 0xBF01: CCLINK_ERR_CYCLIC_TIMEOUT
   - 0xBF02: CCLINK_ERR_TRANSACTION_ID_MISMATCH
   - 0xBF03: CCLINK_ERR_STATION_NUMBER_COLLISION
   - 0xBF04: CCLINK_ERR_FRAME_CRC_CORRUPTED
8. Section 8: Horner OCS register space synchronization with PrivilegeMode.SYSTEM and operator fault reset.
9. Section 9: ILogicUnit interface compliance (execute with ScanContext, reset, name, priority).
10. Section 10: Deterministic 9-stage verification suite integration (run_cclink_basic_verification).
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
import time
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cclink_basic import (
    CCLINK_BASIC_BITS_PER_STATION,
    CCLINK_BASIC_BYTES_PER_STATION,
    CCLINK_BASIC_DEFAULT_PORT,
    CCLINK_BASIC_HEADER_SIZE,
    CCLINK_BASIC_MAGIC,
    CCLINK_BASIC_MAX_OCCUPIED_STATIONS,
    CCLINK_BASIC_MAX_STATION_ID,
    CCLINK_BASIC_NOMINAL_CYCLE_TIME_MS,
    CCLINK_BASIC_NOMINAL_TIMEOUT_MS,
    CCLINK_BASIC_PROTOCOL_VERSION,
    CCLINK_BASIC_PURE_ST_POU,
    CCLINK_BASIC_SLAVE_SYNC_POU,
    CCLINK_BASIC_SYNC_POU,
    CCLINK_BASIC_WORDS_PER_STATION,
    CCLINK_IE_FIELD_BASIC_SYNC_POU,
    PURE_ST_POU,
    CcLinkBasicDiagnosticCode,
    CcLinkBasicError,
    CcLinkBasicFrame,
    CcLinkBasicFrameType,
    CcLinkBasicLinkDevices,
    CcLinkBasicMasterSimulator,
    CcLinkBasicSlaveEngine,
    CcLinkBasicSlaveState,
    CcLinkBasicStatusBits,
    CcLinkCyclicTimeoutError,
    CcLinkFrameCrcError,
    CcLinkIeFieldBasicSlaveEngine,
    CcLinkStationCollisionError,
    CcLinkTransactionIdMismatchError,
    calculate_cclink_crc16,
    decode_station_group_word,
    encode_station_group_word,
    run_cclink_basic_verification,
    scale_time_ms_to_int16,
    unscale_int16_to_time_ms,
    verify_cclink_basic_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def slave_engine(register_table: RegisterTable) -> CcLinkIeFieldBasicSlaveEngine:
    """Provide a fresh slave station engine bound to register table."""
    return CcLinkIeFieldBasicSlaveEngine(
        station_id=1,
        group_id=1,
        occupied_stations=1,
        group_cycle_time_ms=10.0,
        disconnection_timeout_ms=50.0,
        ip_address="192.168.3.10",
        register_table=register_table,
    )


@pytest.fixture
def master_sim() -> CcLinkBasicMasterSimulator:
    """Provide a master station simulator."""
    return CcLinkBasicMasterSimulator(
        master_ip="192.168.3.1",
        group_cycle_time_ms=10.0,
        disconnection_timeout_ms=50.0,
    )


# ============================================================================
# 1. Pure ST POU AST Validation & Register Binding
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for Pure Structured Text POU compliance and register bindings."""

    def test_verify_cclink_basic_pure_st_helper(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_cclink_basic_pure_st() is True

    def test_pure_st_pou_ast_parsing_primary(self) -> None:
        """Parse CCLINK_BASIC_SYNC_POU with STParser and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(CCLINK_BASIC_SYNC_POU)
        assert pou is not None
        assert pou.name == "CcLinkIeFieldBasicSync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "CyclicCycleTimeMsScaled",
            "OccupiedStationsCount",
            "TransactionSequenceCounter",
            "CyclicTimeoutMsScaled",
            "FrameCrcErrorCount",
            "SlaveStationStatusWord",
            "StationNumberAndGroupWord",
            "DiagnosticStatusCode",
            "CcLinkPermissive",
            "CcLinkFaultTrip",
        }
        assert expected_vars.issubset(var_names)

        bound = set(pou.bound_registers)
        expected_regs = {
            "%R1270", "%R1271", "%R1272", "%R1273",
            "%R1274", "%R1275", "%R1276", "%R1277",
            "%M296", "%M297",
        }
        assert bound == expected_regs

    def test_pure_st_pou_ast_parsing_alias(self) -> None:
        """Parse CCLINK_BASIC_SLAVE_SYNC_POU alias with STParser."""
        parser = STParser()
        pou = parser.parse_pou(CCLINK_BASIC_SLAVE_SYNC_POU)
        assert pou is not None
        assert pou.name == "CcLinkIeBasicSlaveSync"
        assert pou.pou_type == POUType.PROGRAM

        bound = set(pou.bound_registers)
        expected_regs = {
            "%R1270", "%R1271", "%R1272", "%R1273",
            "%R1274", "%R1275", "%R1276", "%R1277",
            "%M296", "%M297",
        }
        assert bound == expected_regs

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify both POUs pass SecurityGuard assertion cleanly."""
        SecurityGuard.assert_pure_st_content(CCLINK_BASIC_SYNC_POU)
        SecurityGuard.assert_pure_st_content(CCLINK_BASIC_SLAVE_SYNC_POU)


# ============================================================================
# 2. Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection2AntiLadderSecurityGuard:
    """Tests verifying ladder logic constructs are strictly rejected."""

    def test_ladder_contacts_rejected(self) -> None:
        """Reject ASCII ladder contacts ---[ ]---."""
        bad_st = "PROGRAM BadContacts\nVAR X: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)
        res = STParser.validate_code(bad_st)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"

    def test_ladder_coils_rejected(self) -> None:
        """Reject ASCII ladder coils ---( )---."""
        bad_st = "PROGRAM BadCoils\nVAR Y: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)
        res = STParser.validate_code(bad_st)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"

    def test_ladder_mnemonics_rejected(self) -> None:
        """Reject ladder mnemonics XIC, OTE, etc."""
        bad_st = "PROGRAM BadMnemonics\nVAR Z: BOOL; END_VAR\nRUNG 1: XIC %M1 OTE %M2 END_RUNG\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)
        res = STParser.validate_code(bad_st)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# 3. Frame Encoding, CRC-16 Checksum, & Serialization
# ============================================================================

class TestSection3FrameEncodingAndCrc:
    """Tests for binary frame serialization, CRC-16 verification, and parsing."""

    def test_cyclic_request_frame_roundtrip(self) -> None:
        """Serialize and parse a CYCLIC_REQUEST frame."""
        frame = CcLinkBasicFrame(
            frame_type=CcLinkBasicFrameType.CYCLIC_REQUEST,
            transaction_id=1234,
            station_id=1,
            group_id=2,
            occupied_stations=1,
            cycle_time_scaled=100,
            timeout_scaled=500,
            ry_bits=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            rww_registers=[10, 20, 30, -40],
        )
        data = frame.serialize()
        assert len(data) >= CCLINK_BASIC_HEADER_SIZE + 2

        parsed = CcLinkBasicFrame.parse(data)
        assert parsed.frame_type == CcLinkBasicFrameType.CYCLIC_REQUEST
        assert parsed.transaction_id == 1234
        assert parsed.station_id == 1
        assert parsed.group_id == 2
        assert parsed.occupied_stations == 1
        assert parsed.cycle_time_scaled == 100
        assert parsed.timeout_scaled == 500
        assert parsed.ry_bits[:8] == b"\x01\x02\x03\x04\x05\x06\x07\x08"
        assert parsed.rww_registers[:4] == [10, 20, 30, -40]
        assert parsed.crc == calculate_cclink_crc16(data[:-2])

    def test_cyclic_response_frame_roundtrip(self) -> None:
        """Serialize and parse a CYCLIC_RESPONSE frame."""
        frame = CcLinkBasicFrame(
            frame_type=CcLinkBasicFrameType.CYCLIC_RESPONSE,
            transaction_id=5678,
            station_id=3,
            group_id=1,
            occupied_stations=1,
            cycle_time_scaled=100,
            timeout_scaled=500,
            rx_bits=b"\xFF\x00\xAA\x55\x00\x00\x00\x00",
            rwr_registers=[1000, 2000, 3000, 4000],
        )
        data = frame.serialize()
        parsed = CcLinkBasicFrame.parse(data)
        assert parsed.frame_type == CcLinkBasicFrameType.CYCLIC_RESPONSE
        assert parsed.transaction_id == 5678
        assert parsed.station_id == 3
        assert parsed.rx_bits[:4] == b"\xFF\x00\xAA\x55"
        assert parsed.rwr_registers[:4] == [1000, 2000, 3000, 4000]

    def test_corrupted_crc_raises_exception(self) -> None:
        """Verify corrupted CRC-16 checksum triggers CcLinkFrameCrcError."""
        frame = CcLinkBasicFrame(
            frame_type=CcLinkBasicFrameType.CYCLIC_REQUEST,
            transaction_id=1,
            station_id=1,
        )
        data = bytearray(frame.serialize())
        data[-1] ^= 0xFF  # Flip bit in CRC
        with pytest.raises(CcLinkFrameCrcError, match="CRC corrupted"):
            CcLinkBasicFrame.parse(bytes(data))

    def test_truncated_frame_raises_exception(self) -> None:
        """Verify truncated frame bytes trigger CcLinkFrameCrcError."""
        with pytest.raises(CcLinkFrameCrcError, match="truncated"):
            CcLinkBasicFrame.parse(b"\x00\x01\x02")

    def test_invalid_magic_raises_exception(self) -> None:
        """Verify incorrect header magic triggers CcLinkFrameCrcError."""
        frame = CcLinkBasicFrame(
            frame_type=CcLinkBasicFrameType.CYCLIC_REQUEST,
            transaction_id=1,
            station_id=1,
        )
        data = bytearray(frame.serialize())
        data[0:4] = b"BADM"
        with pytest.raises(CcLinkFrameCrcError, match="Invalid header magic"):
            CcLinkBasicFrame.parse(bytes(data))


# ============================================================================
# 4. Link Devices Storage Container (RX, RY, RWw, RWr)
# ============================================================================

class TestSection4LinkDevicesContainer:
    """Tests for link device manipulation and atomic double buffering."""

    def test_link_device_bit_access(self) -> None:
        """Verify individual bit access for RX and RY."""
        dev = CcLinkBasicLinkDevices(occupied_stations=1)
        assert dev.num_bits == 64
        assert dev.num_words == 32

        # RX bit write in shadow and read
        dev.set_rx_bit(0, True)
        dev.set_rx_bit(63, True)
        assert dev.get_rx_bit(0) is True
        assert dev.get_rx_bit(63) is True
        assert dev.get_rx_bit(1) is False

        # RY bit write in working and commit to shadow
        dev.set_ry_bit(7, True)
        dev.commit_inbound()
        assert dev.get_ry_bit(7) is True

    def test_link_device_word_access(self) -> None:
        """Verify 16-bit word access for RWw and RWr."""
        dev = CcLinkBasicLinkDevices(occupied_stations=1)

        dev.set_rww_word(0, 1234)
        dev.set_rww_word(31, -5678)
        dev.commit_inbound()
        assert dev.get_rww_word(0) == 1234
        assert dev.get_rww_word(31) == -5678

        dev.set_rwr_word(5, 9999)
        assert dev.get_rwr_word(5) == 9999

    def test_link_device_out_of_bounds_handling(self) -> None:
        """Verify out-of-bounds point and word indices raise IndexError."""
        dev = CcLinkBasicLinkDevices(occupied_stations=1)
        with pytest.raises(IndexError):
            dev.get_rx_bit(64)
        with pytest.raises(IndexError):
            dev.get_rww_word(32)

    def test_multi_station_link_device_sizing(self) -> None:
        """Verify allocation scales proportionally with occupied stations."""
        dev2 = CcLinkBasicLinkDevices(occupied_stations=2)
        assert dev2.num_bits == 128
        assert dev2.num_bytes == 16
        assert dev2.num_words == 64


# ============================================================================
# 5. Slave Station Diagnostic State Machine Lifecycle
# ============================================================================

class TestSection5StateMachineLifecycle:
    """Tests for slave state machine transitions and initialization."""

    def test_state_machine_initial_to_operational(
        self,
        slave_engine: CcLinkIeFieldBasicSlaveEngine,
        master_sim: CcLinkBasicMasterSimulator,
    ) -> None:
        """Test sequence: DISCONNECTED -> LINK_SCAN_WAIT -> CYCLIC_OPERATION."""
        assert slave_engine.state == CcLinkBasicSlaveState.DISCONNECTED
        assert slave_engine.permissive is False
        assert slave_engine.fault_trip is False

        slave_engine.start_link_scan()
        assert slave_engine.state == CcLinkBasicSlaveState.LINK_SCAN_WAIT

        # First incoming cyclic frame establishes operational state
        resp = master_sim.send_cyclic_request(slave_engine)
        assert resp is not None
        assert slave_engine.state == CcLinkBasicSlaveState.CYCLIC_OPERATION
        assert slave_engine.permissive is True
        assert slave_engine.fault_trip is False
        assert slave_engine.diagnostic_code == CcLinkBasicDiagnosticCode.OK

    def test_unaddressed_frame_ignored(
        self,
        slave_engine: CcLinkIeFieldBasicSlaveEngine,
        master_sim: CcLinkBasicMasterSimulator,
    ) -> None:
        """Verify frame addressed to another station is ignored."""
        slave_engine.start_link_scan()
        req = master_sim.build_cyclic_request(station_id=99)
        resp = slave_engine.handle_cyclic_request(req)
        assert resp is None
        assert slave_engine.state == CcLinkBasicSlaveState.LINK_SCAN_WAIT


# ============================================================================
# 6. Group Cycle Time Tracking & Timing Surveillance
# ============================================================================

class TestSection6TimingSurveillance:
    """Tests for group cycle time tracking (%R1270) and scaling functions."""

    def test_cycle_time_scaling_functions(self) -> None:
        """Verify scaling and unscaling between ms and INT16."""
        assert scale_time_ms_to_int16(10.0) == 100
        assert scale_time_ms_to_int16(50.0) == 500
        assert scale_time_ms_to_int16(0.5) == 5
        assert unscale_int16_to_time_ms(100) == 10.0
        assert unscale_int16_to_time_ms(500) == 50.0

    def test_station_group_word_encoding(self) -> None:
        """Verify station ID and group ID packing into UINT16 word (%R1276)."""
        word = encode_station_group_word(station_id=1, group_id=2)
        st, grp = decode_station_group_word(word)
        assert st == 1
        assert grp == 2

    def test_nominal_cyclic_exchange_monotonic_sequence(
        self,
        slave_engine: CcLinkIeFieldBasicSlaveEngine,
        master_sim: CcLinkBasicMasterSimulator,
    ) -> None:
        """Verify smooth monotonic sequence increment across scan steps."""
        slave_engine.start_link_scan()
        for i in range(1, 11):
            resp = master_sim.send_cyclic_request(slave_engine)
            assert resp is not None
            telemetry = slave_engine.scan_step(dt=0.01)
            assert telemetry["state"] == "CYCLIC_OPERATION"
            assert slave_engine.reg_table.read_uword("%R1272") == i
            assert slave_engine.reg_table.read_word("%R1270") == 100


# ============================================================================
# 7. Process Safety Trips & Interlock Assertions
# ============================================================================

class TestSection7ProcessSafetyTrips:
    """Tests for all 4 diagnostic failure modes (0xBF01..0xBF04) and coil trips."""

    def test_trip_0xbf01_cyclic_timeout(
        self,
        slave_engine: CcLinkIeFieldBasicSlaveEngine,
        master_sim: CcLinkBasicMasterSimulator,
    ) -> None:
        """0xBF01: Frame timeout > 50.0 ms trips %M297 and clears %M296."""
        slave_engine.start_link_scan()
        master_sim.send_cyclic_request(slave_engine)
        assert slave_engine.permissive is True

        # Advance 55 ms without receiving frame
        slave_engine.scan_step(dt=0.055)

        assert slave_engine.state == CcLinkBasicSlaveState.COMMUNICATION_FAULT
        assert slave_engine.diagnostic_code == CcLinkBasicDiagnosticCode.CCLINK_ERR_CYCLIC_TIMEOUT
        assert slave_engine.reg_table.read_uword("%R1277") == 0xBF01
        assert slave_engine.reg_table.read_bit("%M297") is True
        assert slave_engine.reg_table.read_bit("%M296") is False

    def test_trip_0xbf02_transaction_id_mismatch(
        self,
        slave_engine: CcLinkIeFieldBasicSlaveEngine,
        master_sim: CcLinkBasicMasterSimulator,
    ) -> None:
        """0xBF02: Out-of-order transaction ID trips %M297 and clears %M296."""
        slave_engine.start_link_scan()
        master_sim.send_cyclic_request(slave_engine)
        cur_tx = slave_engine.last_transaction_id

        # Jump transaction ID from cur_tx to cur_tx + 10
        bad_frame = CcLinkBasicFrame(
            frame_type=CcLinkBasicFrameType.CYCLIC_REQUEST,
            transaction_id=(cur_tx + 10) & 0xFFFF,
            station_id=slave_engine.station_id,
            group_id=slave_engine.group_id,
        )
        resp = slave_engine.handle_cyclic_request(bad_frame)
        assert resp is None
        assert slave_engine.state == CcLinkBasicSlaveState.COMMUNICATION_FAULT
        assert slave_engine.diagnostic_code == CcLinkBasicDiagnosticCode.CCLINK_ERR_TRANSACTION_ID_MISMATCH
        assert slave_engine.reg_table.read_uword("%R1277") == 0xBF02
        assert slave_engine.reg_table.read_bit("%M297") is True
        assert slave_engine.reg_table.read_bit("%M296") is False

    def test_trip_0xbf03_station_collision(
        self,
        slave_engine: CcLinkIeFieldBasicSlaveEngine,
        master_sim: CcLinkBasicMasterSimulator,
    ) -> None:
        """0xBF03: Duplicate station ID / IP collision trips %M297 and clears %M296."""
        slave_engine.start_link_scan()
        master_sim.send_cyclic_request(slave_engine)

        slave_engine.detect_station_collision(
            conflicting_ip="192.168.3.99",
            conflicting_station_id=slave_engine.station_id,
        )
        assert slave_engine.state == CcLinkBasicSlaveState.COMMUNICATION_FAULT
        assert slave_engine.diagnostic_code == CcLinkBasicDiagnosticCode.CCLINK_ERR_STATION_NUMBER_COLLISION
        assert slave_engine.reg_table.read_uword("%R1277") == 0xBF03
        assert slave_engine.reg_table.read_bit("%M297") is True
        assert slave_engine.reg_table.read_bit("%M296") is False

    def test_trip_0xbf04_frame_crc_corrupted(
        self,
        slave_engine: CcLinkIeFieldBasicSlaveEngine,
        master_sim: CcLinkBasicMasterSimulator,
    ) -> None:
        """0xBF04: Corrupted frame CRC increments %R1274, trips %M297 and clears %M296."""
        slave_engine.start_link_scan()
        master_sim.send_cyclic_request(slave_engine)

        req = master_sim.build_cyclic_request(station_id=slave_engine.station_id)
        raw = bytearray(req.serialize())
        raw[-2] ^= 0xAA  # Corrupt CRC
        resp_raw = slave_engine.handle_raw_frame(bytes(raw))

        assert resp_raw is None
        assert slave_engine.state == CcLinkBasicSlaveState.COMMUNICATION_FAULT
        assert slave_engine.diagnostic_code == CcLinkBasicDiagnosticCode.CCLINK_ERR_FRAME_CRC_CORRUPTED
        assert slave_engine.reg_table.read_uword("%R1277") == 0xBF04
        assert slave_engine.reg_table.read_word("%R1274") >= 1
        assert slave_engine.reg_table.read_bit("%M297") is True
        assert slave_engine.reg_table.read_bit("%M296") is False


# ============================================================================
# 8. Horner OCS Register Space Synchronization & Fault Reset
# ============================================================================

class TestSection8RegisterSyncAndReset:
    """Tests for Horner OCS memory map bindings and operator fault reset."""

    def test_register_map_complete_sync(
        self,
        slave_engine: CcLinkIeFieldBasicSlaveEngine,
        master_sim: CcLinkBasicMasterSimulator,
    ) -> None:
        """Verify full %R1270..%R1277 and %M296..%M297 layout."""
        slave_engine.start_link_scan()
        master_sim.send_cyclic_request(slave_engine)

        rt = slave_engine.reg_table
        assert rt.read_word("%R1270") == 100
        assert rt.read_word("%R1271") == 1
        assert rt.read_uword("%R1272") == 1
        assert rt.read_word("%R1273") == 500
        assert rt.read_word("%R1274") == 0
        assert rt.read_uword("%R1276") == encode_station_group_word(1, 1)
        assert rt.read_uword("%R1277") == 0x0000
        assert rt.read_bit("%M296") is True
        assert rt.read_bit("%M297") is False

    def test_fault_reset_recovery(
        self,
        slave_engine: CcLinkIeFieldBasicSlaveEngine,
    ) -> None:
        """Verify manual operator reset clears latched fault."""
        slave_engine.trigger_fault(CcLinkBasicDiagnosticCode.CCLINK_ERR_TRANSACTION_ID_MISMATCH)
        assert slave_engine.fault_trip is True

        res = slave_engine.reset_fault(force=True)
        assert res.status == AgentStatus.SUCCESS
        assert slave_engine.fault_trip is False
        assert slave_engine.diagnostic_code == CcLinkBasicDiagnosticCode.OK
        assert slave_engine.reg_table.read_uword("%R1277") == 0x0000
        assert slave_engine.reg_table.read_bit("%M297") is False


# ============================================================================
# 9. ILogicUnit Interface Compliance
# ============================================================================

class TestSection9ILogicUnitCompliance:
    """Tests verifying simulation engine ILogicUnit interface compliance."""

    def test_ilogicunit_properties_and_execution(
        self,
        slave_engine: CcLinkIeFieldBasicSlaveEngine,
    ) -> None:
        """Verify name, priority, execute with ScanContext, and reset."""
        assert slave_engine.name == "cclink_ie_field_basic"
        assert slave_engine.priority == 94
        assert slave_engine.is_enabled is True

        ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=lambda addr: slave_engine.reg_table.read_register(addr),
            set_register=lambda addr, val: slave_engine.reg_table.write_register(addr, val),
            get_variable=lambda k, d=None: None,
            set_variable=lambda k, v: None,
            record_fault=lambda fault: None,
        )
        slave_engine.execute(ctx)
        assert slave_engine.elapsed_time_ms == 10.0

        slave_engine.trigger_fault(CcLinkBasicDiagnosticCode.CCLINK_ERR_CYCLIC_TIMEOUT)
        slave_engine.reset()
        assert slave_engine.fault_trip is False


# ============================================================================
# 10. Deterministic 9-Stage Verification Suite
# ============================================================================

class TestSection10VerificationSuite:
    """Tests executing the 9-stage verification suite and validating output."""

    def test_run_cclink_basic_verification_suite(self) -> None:
        """Run verification suite, assert success, and verify evidence file output."""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            output_file = Path(td) / "cclink_basic_evidence.json"
            res = run_cclink_basic_verification(output_path=output_file)

            assert res["status"] == "success"
            assert res["error_code"] is None
            assert res["data"]["checks_passed"] == 9
            assert res["data"]["total_checks"] == 9

            assert output_file.exists()
            with open(output_file, "r", encoding="utf-8") as f:
                saved_data = json.load(f)
            assert saved_data["status"] == "success"
            assert len(saved_data["data"]["tests"]) == 9
