"""Unit Test Suite for Industrial CC-Link IE Field Master Protocol Engine.

Work Package: W112 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Pure ST POU AST validation and anti-ladder check (verify_cclink_pure_st).
2. Token frame encoding and ring passing.
3. Cyclic I/O transmission (RX, RY, RWw, RWr).
4. Dual-ring loopback fault recovery mechanism.
5. Duplicate station number detection (code 0x8904).
6. Slave disconnect handling (code 0x8901).
7. Cyclic overrun / jitter surveillance (code 0x8903).
8. Horner OCS register space synchronization (%R730..%R737, %M170..%M171).
9. Anti-ladder security guard rejection (LadderForbiddenError on contacts/coils).
10. End-to-end 9-stage verification suite (run_cclink_verification).
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
import struct

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.cclink import (
    CCLINK_BITS_PER_STATION,
    CCLINK_DEFAULT_SCAN_TIME_US,
    CCLINK_ETHERTYPE,
    CCLINK_HEADER_SIZE,
    CCLINK_JITTER_THRESHOLD_RATIO,
    CCLINK_LOOPBACK_MAX_TIME_MS,
    CCLINK_MAX_STATIONS,
    CCLINK_MISSED_TOKEN_OFFLINE_THRESHOLD,
    CCLINK_PURE_ST_POU,
    CCLINK_SPEED_BPS,
    CCLINK_WORDS_PER_STATION,
    CCLinkDiagnosticCode,
    CCLinkFrame,
    CCLinkFrameType,
    CCLinkMasterEngine,
    CCLinkRingTopology,
    CCLinkStationDescriptor,
    CCLinkStatusBits,
    DoubleBufferedCyclicImage,
    run_cclink_verification,
    verify_cclink_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provide a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def cclink_engine(register_table: RegisterTable) -> CCLinkMasterEngine:
    """Provide a fresh CCLinkMasterEngine."""
    return CCLinkMasterEngine(
        reg_table=register_table,
        link_scan_time_us=CCLINK_DEFAULT_SCAN_TIME_US,
    )


# ============================================================================
# 1. Pure ST POU AST Validation & Anti-Ladder Check
# ============================================================================

class TestSection1PureSTPOU:
    """Tests for Pure Structured Text POU compliance and anti-ladder security."""

    def test_verify_cclink_pure_st_function(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_cclink_pure_st() is True

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Parse CCLINK_PURE_ST_POU with STParser and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(CCLINK_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "CCLinkIESync"
        assert pou.pou_type == POUType.PROGRAM

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "CCLinkStatusWord",
            "ConfiguredStationsCount",
            "ActiveStationMaskLow",
            "ActiveStationMaskMid",
            "ActiveStationMaskHigh",
            "LinkScanTimeUs",
            "TotalCyclicFramesTransferred",
            "DiagnosticEventCode",
            "CCLinkNormalActive",
            "CCLinkRingFaultTrip",
        }
        assert expected_vars.issubset(var_names)

        # Verify direct register bindings in AST
        bound = set(pou.bound_registers)
        expected_regs = {
            "%R730", "%R731", "%R732", "%R733", "%R734",
            "%R735", "%R736", "%R737", "%M170", "%M171",
        }
        assert expected_regs.issubset(bound)

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify pure ST POU passes SecurityGuard assertion cleanly."""
        SecurityGuard.assert_pure_st_content(CCLINK_PURE_ST_POU)


# ============================================================================
# 2. Token Frame Encoding & Ring Passing
# ============================================================================

class TestSection2TokenFrameEncodingAndRingPassing:
    """Tests for frame serialization, CRC-32 validation, and token ring rotation."""

    def test_token_frame_serialization_roundtrip(self) -> None:
        """Verify Token frame packing and unpacking with CRC32."""
        frame = CCLinkFrame(
            frame_type=CCLinkFrameType.TOKEN,
            sequence_id=42,
            src_station=0,
            dst_station=1,
            cycle_counter=100,
            ring_topology=CCLinkRingTopology.NORMAL_RING,
            token_holder=0,
        )
        raw = frame.serialize()
        assert len(raw) >= CCLINK_HEADER_SIZE + 4

        unpacked = CCLinkFrame.deserialize(raw)
        assert unpacked.frame_type == CCLinkFrameType.TOKEN
        assert unpacked.sequence_id == 42
        assert unpacked.src_station == 0
        assert unpacked.dst_station == 1
        assert unpacked.cycle_counter == 100
        assert unpacked.ring_topology == CCLinkRingTopology.NORMAL_RING
        assert unpacked.token_holder == 0

    def test_cyclic_data_frame_serialization_roundtrip(self) -> None:
        """Verify Cyclic Data frame with payloads roundtrips cleanly."""
        rx_bytes = b"\x01\x02"
        ry_bytes = b"\x03\x04"
        rww_bytes = struct.pack(">4H", 10, 20, 30, 40)
        rwr_bytes = struct.pack(">4H", 50, 60, 70, 80)

        frame = CCLinkFrame(
            frame_type=CCLinkFrameType.CYCLIC_DATA,
            sequence_id=99,
            src_station=2,
            dst_station=0,
            cycle_counter=101,
            ring_topology=CCLinkRingTopology.NORMAL_RING,
            token_holder=2,
            rx_payload=rx_bytes,
            ry_payload=ry_bytes,
            rww_payload=rww_bytes,
            rwr_payload=rwr_bytes,
        )
        raw = frame.serialize()
        unpacked = CCLinkFrame.deserialize(raw)

        assert unpacked.frame_type == CCLinkFrameType.CYCLIC_DATA
        assert unpacked.rx_payload == rx_bytes
        assert unpacked.ry_payload == ry_bytes
        assert unpacked.rww_payload == rww_bytes
        assert unpacked.rwr_payload == rwr_bytes

    def test_corrupt_crc32_raises_value_error(self) -> None:
        """Verify corrupted CRC-32 raises ValueError."""
        frame = CCLinkFrame(
            frame_type=CCLinkFrameType.TOKEN,
            sequence_id=1,
            src_station=0,
            dst_station=1,
            cycle_counter=1,
        )
        raw = bytearray(frame.serialize())
        raw[-2] ^= 0xFF  # Corrupt CRC byte
        with pytest.raises(ValueError, match="CRC32 mismatch"):
            CCLinkFrame.deserialize(bytes(raw))

    def test_short_frame_raises_value_error(self) -> None:
        """Verify truncated frame raises ValueError."""
        with pytest.raises(ValueError, match="too short"):
            CCLinkFrame.deserialize(b"\x00\x01\x02\x03")

    def test_invalid_ethertype_raises_value_error(self) -> None:
        """Verify mismatched EtherType raises ValueError."""
        frame = CCLinkFrame(
            frame_type=CCLinkFrameType.TOKEN,
            sequence_id=1,
            src_station=0,
            dst_station=1,
            cycle_counter=1,
        )
        raw = bytearray(frame.serialize())
        raw[0] = 0x12  # Overwrite EtherType
        raw[1] = 0x34
        # Recalculate CRC for modified body to pass CRC check and hit EtherType check
        import zlib
        body = raw[:-4]
        new_crc = zlib.crc32(body) & 0xFFFFFFFF
        raw[-4:] = struct.pack(">I", new_crc)

        with pytest.raises(ValueError, match="Invalid EtherType"):
            CCLinkFrame.deserialize(bytes(raw))

    def test_token_ring_rotation_across_stations(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify deterministic token rotation across configured stations."""
        for i in range(1, 4):
            cclink_engine.configure_station(
                CCLinkStationDescriptor(station_no=i, station_name=f"Station_{i}")
            )

        cclink_engine.start_engine()
        assert cclink_engine.master_active is True
        assert cclink_engine.ring_synchronized is True

        res = cclink_engine.execute_token_cycle()
        assert res["polled_count"] == 3
        assert res["cycle_counter"] == 1
        assert res["total_cyclic_frames"] == 3
        assert cclink_engine.cycle_counter == 1


# ============================================================================
# 3. Cyclic I/O Transmission (RX, RY, RWw, RWr)
# ============================================================================

class TestSection3CyclicIOTransmission:
    """Tests for double-buffered cyclic process data transmission."""

    def test_double_buffered_cyclic_image_isolation(self) -> None:
        """Verify working buffer is decoupled from shadow buffer until commit."""
        db = DoubleBufferedCyclicImage()
        db.initialize_station(1)

        # Application writes outputs in working buffer
        db.write_working_ry_bit(station_no=1, bit_index=3, value=True)
        db.write_working_rww_word(station_no=1, word_index=2, value=0xABCD)

        # Shadow buffer should still be untouched
        shadow_ry = db.get_shadow_ry(1)
        shadow_rww = db.get_shadow_rww(1)
        assert shadow_ry[3] is False
        assert shadow_rww[2] == 0

        # Stage incoming network inputs in shadow buffer
        db.stage_network_rx(1, [True] + [False] * 15)
        db.stage_network_rwr(1, [0x1234, 0, 0, 0])

        # Working buffer should not see staged inputs yet
        assert db.read_working_rx_bit(1, 0) is False
        assert db.read_working_rwr_word(1, 0) == 0

        # Commit buffer swap
        db.commit_buffer_swap()

        # Inputs now published to working buffer
        assert db.read_working_rx_bit(1, 0) is True
        assert db.read_working_rwr_word(1, 0) == 0x1234

        # Outputs now latched into shadow buffer for next network dispatch
        assert db.get_shadow_ry(1)[3] is True
        assert db.get_shadow_rww(1)[2] == 0xABCD

    def test_cyclic_data_transfer_engine_integration(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify full scan cycle exchanges cyclic I/O and commits buffers."""
        st1 = CCLinkStationDescriptor(station_no=1)
        st2 = CCLinkStationDescriptor(station_no=2)
        cclink_engine.configure_station(st1)
        cclink_engine.configure_station(st2)
        cclink_engine.start_engine()

        # Master prepares outputs for stations 1 & 2
        cclink_engine.double_buffer.write_working_ry_bit(1, 7, True)
        cclink_engine.double_buffer.write_working_rww_word(1, 0, 0x55AA)
        cclink_engine.double_buffer.write_working_ry_bit(2, 2, True)
        cclink_engine.double_buffer.write_working_rww_word(2, 3, 0x1122)

        # Stations provide inputs
        st1.rx_bits[4] = True
        st1.rwr_words[1] = 0x7788
        st2.rx_bits[11] = True
        st2.rwr_words[2] = 0x99AA

        cclink_engine.execute_token_cycle()

        # Master working buffer received inputs
        assert cclink_engine.double_buffer.read_working_rx_bit(1, 4) is True
        assert cclink_engine.double_buffer.read_working_rwr_word(1, 1) == 0x7788
        assert cclink_engine.double_buffer.read_working_rx_bit(2, 11) is True
        assert cclink_engine.double_buffer.read_working_rwr_word(2, 2) == 0x99AA

        # Stations received master's outputs
        assert st1.ry_bits[7] is True
        assert st1.rww_words[0] == 0x55AA
        assert st2.ry_bits[2] is True
        assert st2.rww_words[3] == 0x1122


# ============================================================================
# 4. Dual-Ring Loopback Fault Recovery Mechanism
# ============================================================================

class TestSection4DualRingLoopbackRecovery:
    """Tests for dual-ring loopback recovery latency and folded ring continuity."""

    def test_cable_sever_triggers_loopback(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify severing cable between adjacent stations triggers loopback (< 10 ms)."""
        for i in range(1, 5):
            cclink_engine.configure_station(CCLinkStationDescriptor(station_no=i))
        cclink_engine.start_engine()

        rec_time = cclink_engine.sever_cable(station_a=2, station_b=3)
        assert rec_time < CCLINK_LOOPBACK_MAX_TIME_MS
        assert cclink_engine.loopback_active is True
        assert bool(cclink_engine.status_bits & CCLinkStatusBits.LOOPBACK_ACTIVE) is True
        assert cclink_engine.diagnostic_code == CCLinkDiagnosticCode.TOKEN_LOSS_LOOPBACK
        assert int(cclink_engine.diagnostic_code) == 0x8902

        # Verify %R730 and %R737 register update
        r730 = cclink_engine.reg_table.read_uword("%R730")
        r737 = cclink_engine.reg_table.read_uword("%R737")
        assert (r730 & int(CCLinkStatusBits.LOOPBACK_ACTIVE)) != 0
        assert r737 == 0x8902

    def test_token_and_cyclic_exchange_continues_under_loopback(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify folded loopback ring maintains communication to all stations."""
        for i in range(1, 5):
            cclink_engine.configure_station(CCLinkStationDescriptor(station_no=i))
        cclink_engine.start_engine()

        cclink_engine.sever_cable(2, 3)
        res = cclink_engine.execute_token_cycle()

        assert res["polled_count"] == 4
        assert res["loopback_active"] is True
        assert len(res["active_stations"]) == 4

    def test_cable_restoration_clears_loopback(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify restoring severed cable returns ring to normal closed mode."""
        for i in range(1, 5):
            cclink_engine.configure_station(CCLinkStationDescriptor(station_no=i))
        cclink_engine.start_engine()

        cclink_engine.sever_cable(2, 3)
        assert cclink_engine.loopback_active is True

        cclink_engine.restore_cable()
        assert cclink_engine.loopback_active is False
        assert bool(cclink_engine.status_bits & CCLinkStatusBits.LOOPBACK_ACTIVE) is False
        assert cclink_engine.diagnostic_code == CCLinkDiagnosticCode.OK

        r730 = cclink_engine.reg_table.read_uword("%R730")
        r737 = cclink_engine.reg_table.read_uword("%R737")
        assert (r730 & int(CCLinkStatusBits.LOOPBACK_ACTIVE)) == 0
        assert r737 == 0x0000


# ============================================================================
# 5. Duplicate Station Number Detection (Code 0x8904)
# ============================================================================

class TestSection5DuplicateStationDetection:
    """Tests for duplicate station collision detection and fail-safe latching."""

    def test_duplicate_station_registration_raises_error(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify registering an already-configured station number is rejected."""
        cclink_engine.configure_station(CCLinkStationDescriptor(station_no=5))
        with pytest.raises(ValueError, match="DUPLICATE_STATION_NO"):
            cclink_engine.configure_station(CCLinkStationDescriptor(station_no=5))

    def test_duplicate_station_asserts_code_0x8904_and_alarm_bit(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify duplicate station collision sets 0x8904 and DUP_STATION_ALARM bit."""
        cclink_engine.configure_station(CCLinkStationDescriptor(station_no=7))
        try:
            cclink_engine.configure_station(CCLinkStationDescriptor(station_no=7))
        except ValueError:
            pass

        assert cclink_engine.duplicate_station_detected is True
        assert bool(cclink_engine.status_bits & CCLinkStatusBits.DUP_STATION_ALARM) is True
        assert cclink_engine.diagnostic_code == CCLinkDiagnosticCode.DUPLICATE_STATION_NO
        assert int(cclink_engine.diagnostic_code) == 0x8904

        # Register reflection
        assert cclink_engine.reg_table.read_uword("%R737") == 0x8904
        assert (cclink_engine.reg_table.read_uword("%R730") & int(CCLinkStatusBits.DUP_STATION_ALARM)) != 0

    def test_duplicate_station_trips_fault_coil_m171(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify duplicate station collision sets %M171=TRUE and %M170=FALSE."""
        cclink_engine.configure_station(CCLinkStationDescriptor(station_no=8))
        cclink_engine.start_engine()
        assert cclink_engine.reg_table.read_bit("%M170") is True
        assert cclink_engine.reg_table.read_bit("%M171") is False

        cclink_engine.inject_duplicate_station_collision(8)
        assert cclink_engine.reg_table.read_bit("%M171") is True
        assert cclink_engine.reg_table.read_bit("%M170") is False

    def test_out_of_bounds_station_number_rejected(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify stations outside 1..48 are rejected."""
        with pytest.raises(ValueError):
            CCLinkStationDescriptor(station_no=0)
        with pytest.raises(ValueError):
            CCLinkStationDescriptor(station_no=49)


# ============================================================================
# 6. Slave Disconnect Handling (Code 0x8901)
# ============================================================================

class TestSection6SlaveDisconnectHandling:
    """Tests for slave non-responsiveness and disconnect diagnostic event (0x8901)."""

    def test_missed_cycles_watchdog_threshold(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify 1 or 2 missed cycles does not disconnect; 3 missed cycles disconnects."""
        cclink_engine.configure_station(CCLinkStationDescriptor(station_no=3))
        cclink_engine.start_engine()

        # Missed 1 cycle
        cclink_engine.simulate_slave_missed_cycle(station_no=3, cycles=1)
        assert cclink_engine.configured_stations[3].is_online is True
        assert bool(cclink_engine.status_bits & CCLinkStatusBits.SLAVE_OFFLINE_ALARM) is False

        # Missed 2nd cycle (total 2 < 3)
        cclink_engine.simulate_slave_missed_cycle(station_no=3, cycles=1)
        assert cclink_engine.configured_stations[3].is_online is True

        # Missed 3rd cycle (total 3 >= threshold)
        cclink_engine.simulate_slave_missed_cycle(station_no=3, cycles=1)
        assert cclink_engine.configured_stations[3].is_online is False
        assert bool(cclink_engine.status_bits & CCLinkStatusBits.SLAVE_OFFLINE_ALARM) is True
        assert cclink_engine.diagnostic_code == CCLinkDiagnosticCode.SLAVE_DISCONNECTED
        assert int(cclink_engine.diagnostic_code) == 0x8901

    def test_slave_disconnect_trips_fault_coil_m171(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify slave disconnection sets %M171=TRUE and %M170=FALSE."""
        cclink_engine.configure_station(CCLinkStationDescriptor(station_no=4))
        cclink_engine.start_engine()

        cclink_engine.simulate_slave_missed_cycle(station_no=4, cycles=3)
        cclink_engine.execute_token_cycle()

        assert cclink_engine.reg_table.read_bit("%M171") is True
        assert cclink_engine.reg_table.read_bit("%M170") is False
        assert cclink_engine.reg_table.read_uword("%R737") == 0x8901

    def test_slave_recovery_restores_normal_operation(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify recovering offline slave clears alarm and restores %M170=TRUE."""
        cclink_engine.configure_station(CCLinkStationDescriptor(station_no=4))
        cclink_engine.start_engine()

        cclink_engine.simulate_slave_missed_cycle(station_no=4, cycles=3)
        assert cclink_engine.reg_table.read_bit("%M171") is True

        cclink_engine.recover_slave(station_no=4)
        cclink_engine.execute_token_cycle()

        assert cclink_engine.configured_stations[4].is_online is True
        assert bool(cclink_engine.status_bits & CCLinkStatusBits.SLAVE_OFFLINE_ALARM) is False
        assert cclink_engine.diagnostic_code == CCLinkDiagnosticCode.OK
        assert cclink_engine.reg_table.read_bit("%M170") is True
        assert cclink_engine.reg_table.read_bit("%M171") is False


# ============================================================================
# 7. Cyclic Overrun / Jitter Surveillance (Code 0x8903)
# ============================================================================

class TestSection7CyclicOverrunJitterSurveillance:
    """Tests for scan time period surveillance and 5.0% jitter alarm."""

    def test_nominal_scan_time_zero_jitter(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify nominal 250 us scan produces zero jitter and no warning."""
        cclink_engine.configure_station(CCLinkStationDescriptor(station_no=1))
        cclink_engine.start_engine()

        res = cclink_engine.execute_token_cycle(simulated_scan_time_us=250.0)
        assert res["jitter_percent"] == 0.0
        assert bool(cclink_engine.status_bits & CCLinkStatusBits.JITTER_WARNING) is False
        assert cclink_engine.diagnostic_code == CCLinkDiagnosticCode.OK

    def test_acceptable_jitter_within_5_percent(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify jitter below 5% (e.g. 260 us = 4.0% jitter) does not trip warning."""
        cclink_engine.configure_station(CCLinkStationDescriptor(station_no=1))
        cclink_engine.start_engine()

        res = cclink_engine.execute_token_cycle(simulated_scan_time_us=260.0)
        assert res["jitter_percent"] == pytest.approx(4.0, abs=0.1)
        assert bool(cclink_engine.status_bits & CCLinkStatusBits.JITTER_WARNING) is False

    def test_severe_jitter_exceeding_5_percent_triggers_alarm_0x8903(
        self, cclink_engine: CCLinkMasterEngine
    ) -> None:
        """Verify jitter above 5% (e.g. 270 us = 8.0% jitter) trips CYCLIC_OVERRUN (0x8903)."""
        cclink_engine.configure_station(CCLinkStationDescriptor(station_no=1))
        cclink_engine.start_engine()

        res = cclink_engine.execute_token_cycle(simulated_scan_time_us=270.0)
        assert res["jitter_percent"] == pytest.approx(8.0, abs=0.1)
        assert bool(cclink_engine.status_bits & CCLinkStatusBits.JITTER_WARNING) is True
        assert cclink_engine.diagnostic_code == CCLinkDiagnosticCode.CYCLIC_OVERRUN
        assert int(cclink_engine.diagnostic_code) == 0x8903

        # Register reflection
        r737 = cclink_engine.reg_table.read_uword("%R737")
        r730 = cclink_engine.reg_table.read_uword("%R730")
        assert r737 == 0x8903
        assert (r730 & int(CCLinkStatusBits.JITTER_WARNING)) != 0

    def test_jitter_clears_upon_scan_recovery(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify returning to nominal scan clears JITTER_WARNING and restores OK code."""
        cclink_engine.configure_station(CCLinkStationDescriptor(station_no=1))
        cclink_engine.start_engine()

        cclink_engine.execute_token_cycle(simulated_scan_time_us=280.0)
        assert bool(cclink_engine.status_bits & CCLinkStatusBits.JITTER_WARNING) is True

        cclink_engine.execute_token_cycle(simulated_scan_time_us=250.0)
        assert bool(cclink_engine.status_bits & CCLinkStatusBits.JITTER_WARNING) is False
        assert cclink_engine.diagnostic_code == CCLinkDiagnosticCode.OK


# ============================================================================
# 8. Horner OCS Register Space Synchronization (%R730..%R737, %M170..%M171)
# ============================================================================

class TestSection8HornerRegisterSynchronization:
    """Tests for %R730..%R737 and %M170..%M171 memory synchronization."""

    def test_configured_stations_count_r731(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify %R731 accurately reflects configured station count."""
        assert cclink_engine.reg_table.read_word("%R731") == 0
        cclink_engine.configure_station(CCLinkStationDescriptor(1))
        assert cclink_engine.reg_table.read_word("%R731") == 1
        cclink_engine.configure_station(CCLinkStationDescriptor(2))
        assert cclink_engine.reg_table.read_word("%R731") == 2

    def test_active_station_masks_r732_r733_r734(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify %R732 (1..16), %R733 (17..32), and %R734 (33..48) station online masks."""
        # Nodes 1 & 16 (Low)
        cclink_engine.configure_station(CCLinkStationDescriptor(1))
        cclink_engine.configure_station(CCLinkStationDescriptor(16))
        # Node 17 (Mid)
        cclink_engine.configure_station(CCLinkStationDescriptor(17))
        # Node 48 (High)
        cclink_engine.configure_station(CCLinkStationDescriptor(48))

        mask_low = cclink_engine.reg_table.read_uword("%R732")
        mask_mid = cclink_engine.reg_table.read_uword("%R733")
        mask_high = cclink_engine.reg_table.read_uword("%R734")

        assert mask_low == (1 << 0) | (1 << 15)   # 0x8001
        assert mask_mid == (1 << 0)               # 0x0001
        assert mask_high == (1 << 15)             # 0x8000

    def test_scan_time_r735_and_total_cyclic_frames_r736(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify %R735 (Scan Time) and %R736 (Total Frames) registers."""
        cclink_engine.configure_station(CCLinkStationDescriptor(1))
        cclink_engine.start_engine()

        assert cclink_engine.reg_table.read_word("%R735") == CCLINK_DEFAULT_SCAN_TIME_US
        assert cclink_engine.reg_table.read_word("%R736") == 0

        cclink_engine.execute_token_cycle()
        assert cclink_engine.reg_table.read_word("%R736") == 1

        cclink_engine.execute_token_cycle()
        assert cclink_engine.reg_table.read_word("%R736") == 2

    def test_discrete_coils_truth_table(self, cclink_engine: CCLinkMasterEngine) -> None:
        """Verify %M170 (Normal Active) and %M171 (Fault Trip) boolean states."""
        # Initially not started -> %M170=False, %M171=False
        assert cclink_engine.reg_table.read_bit("%M170") is False
        assert cclink_engine.reg_table.read_bit("%M171") is False

        # Started with 1 online station -> %M170=True, %M171=False
        cclink_engine.configure_station(CCLinkStationDescriptor(1))
        cclink_engine.start_engine()
        assert cclink_engine.reg_table.read_bit("%M170") is True
        assert cclink_engine.reg_table.read_bit("%M171") is False

        # Loopback engaged -> %M170 drops to False (not normal ring)
        cclink_engine.configure_station(CCLinkStationDescriptor(2))
        cclink_engine.sever_cable(1, 2)
        assert cclink_engine.reg_table.read_bit("%M170") is False


# ============================================================================
# 9. Anti-Ladder Security Guard Rejection
# ============================================================================

class TestSection9AntiLadderSecurityGuard:
    """Tests for rejection of ladder logic constructs, coils, and mnemonics."""

    def test_ladder_contacts_rejected(self) -> None:
        """Verify ladder contacts '---[ ]---' trigger LadderForbiddenError."""
        bad_pou = CCLINK_PURE_ST_POU + "\n---[ ]---"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_pou)

    def test_ladder_negative_contacts_rejected(self) -> None:
        """Verify ladder negative contacts '---[/]---' trigger LadderForbiddenError."""
        bad_pou = CCLINK_PURE_ST_POU + "\n---[/]---"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_pou)

    def test_ladder_coils_rejected(self) -> None:
        """Verify ladder coils '---( )---' trigger LadderForbiddenError."""
        bad_pou = CCLINK_PURE_ST_POU + "\n---( )---"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_pou)

    def test_ladder_rungs_and_networks_rejected(self) -> None:
        """Verify RUNG and NETWORK delimiters trigger LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(CCLINK_PURE_ST_POU + "\nRUNG 1: XIC Start")

        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(CCLINK_PURE_ST_POU + "\nNETWORK 1")

    def test_st_parser_validate_code_ladder_rejection(self) -> None:
        """Verify STParser.validate_code catches ladder constructs with ERR_LADDER_FORBIDDEN."""
        res = STParser.validate_code("PROGRAM BadLadder\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM")
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# 10. End-to-End Deterministic Verification Suite
# ============================================================================

class TestSection10EndToEndVerificationSuite:
    """Tests for the complete 9-stage verification suite runner."""

    def test_run_cclink_verification_returns_strict_4_state_success(self) -> None:
        """Verify run_cclink_verification returns strict 4-state contract success."""
        evidence = run_cclink_verification()
        assert evidence["status"] == "success"
        assert evidence["error_code"] is None
        assert "CC-Link IE Field 1 Gbit/s Cyclic Token Ring Protocol Engine verified cleanly" in evidence["details"]

        checks_passed = evidence["data"]["checks_passed"]
        total_checks = evidence["data"]["total_checks"]
        assert checks_passed == total_checks == 9

        tests = evidence["data"]["tests"]
        assert len(tests) == 9
        for t in tests:
            assert t["passed"] is True

    def test_run_cclink_verification_emits_json_artifact(self, tmp_path: Path) -> None:
        """Verify verification suite writes valid JSON evidence artifact to disk."""
        out_file = tmp_path / "cclink_evidence.json"
        evidence = run_cclink_verification(str(out_file))

        assert out_file.is_file()
        with open(out_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W112"
        assert data["data"]["register_map"]["status_word"] == "%R730"
        assert data["data"]["register_map"]["configured_stations_count"] == "%R731"
        assert data["data"]["register_map"]["fault_trip_coil"] == "%M171"
