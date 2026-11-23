"""Unit Test Suite for Industrial IO-Link Wireless (IEC 61131-9 Extension) Protocol Engine & Multi-Track Master Manager.

Work Package: W133 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY

Covers:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R940..%R947, %M219..%M220).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: W-Cycle 5ms real-time subframe timing, downlink/uplink slot allocation, and frequency hopping sequence.
4. Section 4: Multi-track allocation (5 tracks, up to 40 devices) and coexistence management.
5. Section 5: Process Data (PD) and On-Request Data (OD) encoding/decoding and engineering scaling.
6. Section 6: Process safety trips (0x9E01, 0x9E02, 0x9E03, 0x9E04) and Horner coil assertion (%M219, %M220).
7. Section 7: Horner OCS register space synchronization (%R940..%R947, %M219..%M220).
8. Section 8: 9-stage verification suite integration test writing evidence JSON.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import pytest
import struct
import time
from typing import Any, Dict

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.telemetry.iolink_wireless import (
    DEFAULT_W_MASTER_ID,
    DEFAULT_WATCHDOG_TIMEOUT_S,
    IOLINK_WIRELESS_CHANNELS,
    IOLINK_WIRELESS_NETWORK_SYNC_PURE_ST_POU,
    IOLINK_WIRELESS_PURE_ST_POU,
    IOLINK_WIRELESS_TRACK_SYNC_PURE_ST_POU,
    MAX_DEVICES,
    MAX_DEVICES_PER_TRACK,
    MAX_TRACKS,
    NUM_CHANNELS,
    PER_ALARM_THRESHOLD,
    SUBFRAME_DURATION_MS,
    SUBFRAME_DURATION_US,
    SUBFRAMES_PER_CYCLE,
    W_CYCLE_DURATION_MS,
    W_CYCLE_DURATION_S,
    W_CYCLE_TIMEOUT_S,
    WIFI_CHANNELS_24GHZ,
    CRCIntegrityError,
    CoexistenceError,
    IOLinkWirelessDevice,
    IOLinkWirelessDeviceState,
    IOLinkWirelessDiagnosticCode,
    IOLinkWirelessError,
    IOLinkWirelessMaster,
    IOLinkWirelessMultiTrackManager,
    IOLinkWirelessODRequest,
    IOLinkWirelessODResponse,
    IOLinkWirelessProcessDataPayload,
    IOLinkWirelessSlotType,
    IOLinkWirelessStatusBits,
    IOLinkWirelessSubframe,
    OnRequestDataError,
    ProcessDataDecodeError,
    TrackAllocationError,
    WCycleSchedule,
    WCycleTimingError,
    calc_crc16,
    calc_iolink_wireless_hopping_channel,
    decode_od_request,
    decode_od_response,
    decode_process_data,
    encode_od_request,
    encode_od_response,
    encode_process_data,
    generate_track_hopping_sequence,
    get_wifi_coexistence_blacklist,
    run_iolink_wireless_verification,
    scale_pv_to_int16,
    verify_crc16,
    verify_iolink_wireless_pure_st,
)


@pytest.fixture
def register_table() -> RegisterTable:
    """Provides a fresh Horner OCS register table."""
    return RegisterTable()


@pytest.fixture
def wireless_master(register_table: RegisterTable) -> IOLinkWirelessMaster:
    """Provides a fresh IOLinkWirelessMaster initialized with register table."""
    return IOLinkWirelessMaster(reg_table=register_table)


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding, & STParser Validation
# ============================================================================


class TestSection1PureSTPOU:
    """Tests for IEC 61131-3 Pure ST POU compliance, AST verification, and register bindings."""

    def test_verify_iolink_wireless_pure_st_function(self) -> None:
        """Verify the built-in pure ST validation helper returns True."""
        assert verify_iolink_wireless_pure_st() is True

    def test_pure_st_master_sync_pou_ast_parsing(self) -> None:
        """Parse IOLINK_WIRELESS_PURE_ST_POU (IOLinkWirelessMasterSync) and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(IOLINK_WIRELESS_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "IOLinkWirelessMasterSync"
        assert pou.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R940", "%R941", "%R942", "%R943", "%R944",
            "%R945", "%R946", "%R947", "%M219", "%M220",
        }
        assert expected_regs.issubset(set(pou.bound_registers))

        var_names = {v.name for v in pou.variables}
        expected_vars = {
            "IOLinkWirelessStatusWord",
            "ActiveDevicesCount",
            "ActiveTracksMask",
            "PrimaryVariablePvScaled",
            "SecondaryVariableSvScaled",
            "AverageRssi",
            "WCycleCounter",
            "DiagnosticEventCode",
            "IOLinkWirelessActive",
            "IOLinkWirelessFaultTrip",
            "NetworkActiveBit",
            "WCycleSyncBit",
            "FrequencyHoppingBit",
            "MultiTrackActiveBit",
            "WCycleTimeoutTripBit",
            "RfInterferenceAlarmBit",
            "TrackCollisionAlarmBit",
            "DeviceDisconnectTripBit",
            "DiagnosticTrip",
        }
        assert expected_vars.issubset(var_names)

    def test_pure_st_track_sync_pou_ast_parsing(self) -> None:
        """Parse IOLINK_WIRELESS_TRACK_SYNC_PURE_ST_POU and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(IOLINK_WIRELESS_TRACK_SYNC_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "IOLinkWirelessTrackSync"
        assert pou.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R940", "%R941", "%R942", "%R943", "%R944",
            "%R945", "%R946", "%R947", "%M219", "%M220",
        }
        assert expected_regs.issubset(set(pou.bound_registers))

    def test_pure_st_network_sync_pou_ast_parsing(self) -> None:
        """Parse IOLINK_WIRELESS_NETWORK_SYNC_PURE_ST_POU and assert AST attributes."""
        parser = STParser()
        pou = parser.parse_pou(IOLINK_WIRELESS_NETWORK_SYNC_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "IOLinkWirelessNetworkSync"
        assert pou.pou_type == POUType.PROGRAM

        expected_regs = {
            "%R940", "%R941", "%R942", "%R943", "%R944",
            "%R945", "%R946", "%R947", "%M219", "%M220",
        }
        assert expected_regs.issubset(set(pou.bound_registers))

    def test_pure_st_security_guard_assertion(self) -> None:
        """Verify pure ST POUs pass SecurityGuard pure ST assertion cleanly."""
        SecurityGuard.assert_pure_st_content(IOLINK_WIRELESS_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(IOLINK_WIRELESS_TRACK_SYNC_PURE_ST_POU)
        SecurityGuard.assert_pure_st_content(IOLINK_WIRELESS_NETWORK_SYNC_PURE_ST_POU)


# ============================================================================
# Section 2: Anti-Ladder Security Guard Asserting LadderForbiddenError
# ============================================================================


class TestSection2AntiLadderSecurity:
    """Tests for SecurityGuard strict rejection of ladder logic constructs."""

    @pytest.mark.parametrize(
        "sample",
        [
            "PROGRAM BadContacts\nVAR Flag: BOOL; END_VAR\n---[ ]---( )---\nEND_PROGRAM",
            "PROGRAM BadNegative\nVAR Flag: BOOL; END_VAR\n---[/]---\nEND_PROGRAM",
            "PROGRAM BadRung\nVAR Flag: BOOL; END_VAR\nRUNG 1: XIC %M219 OTE %M220 END_RUNG\nEND_PROGRAM",
            "PROGRAM BadCoil\nVAR Out: BOOL; END_VAR\n---(S)---\nEND_PROGRAM",
            "PROGRAM BadReset\nVAR Out: BOOL; END_VAR\n---(R)---\nEND_PROGRAM",
            "PROGRAM BadMnemonic\nVAR Out: BOOL; END_VAR\nXIO %M219\nEND_PROGRAM",
            "PROGRAM BadLatch\nVAR Out: BOOL; END_VAR\nOTL %M220\nEND_PROGRAM",
            "PROGRAM BadNetwork\nVAR X: BOOL; END_VAR\nNETWORK 1\nEND_PROGRAM",
        ],
    )
    def test_ladder_constructs_raise_ladder_forbidden_error(self, sample: str) -> None:
        """Verify embedded ladder constructs raise LadderForbiddenError."""
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(sample)

        res = STParser.validate_code(sample)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "ERR_LADDER_FORBIDDEN"


# ============================================================================
# Section 3: W-Cycle 5ms Timing, Subframe Allocation, & Hopping Sequence
# ============================================================================


class TestSection3WCycleTimingAndHopping:
    """Tests for W-Cycle 5ms real-time subframe timing, downlink/uplink slot allocation, and frequency hopping."""

    def test_w_cycle_duration_and_constants(self) -> None:
        """Verify W-Cycle timing constants: 5ms cycle, 10 subframes, 500us subframe duration."""
        assert W_CYCLE_DURATION_MS == 5
        assert math.isclose(W_CYCLE_DURATION_S, 0.005, abs_tol=1e-6)
        assert SUBFRAME_DURATION_US == 500
        assert math.isclose(SUBFRAME_DURATION_MS, 0.5, abs_tol=1e-6)
        assert SUBFRAMES_PER_CYCLE == 10
        assert NUM_CHANNELS == 80
        assert len(IOLINK_WIRELESS_CHANNELS) == 80

    def test_subframe_creation_and_bounds_validation(self) -> None:
        """Verify subframe parameter validation and boundary enforcement."""
        sf = IOLinkWirelessSubframe(
            subframe_index=0,
            slot_type=IOLinkWirelessSlotType.DOWNLINK,
            track_id=1,
            device_slot=0,
            channel_offset=5,
        )
        assert sf.subframe_index == 0
        assert sf.slot_type == IOLinkWirelessSlotType.DOWNLINK
        assert sf.track_id == 1
        assert sf.device_slot == 0
        assert sf.channel_offset == 5

        # Invalid subframe index < 0 or >= 10
        with pytest.raises(WCycleTimingError, match="Subframe index"):
            IOLinkWirelessSubframe(subframe_index=-1, slot_type=IOLinkWirelessSlotType.UPLINK, track_id=1, device_slot=0)

        with pytest.raises(WCycleTimingError, match="Subframe index"):
            IOLinkWirelessSubframe(subframe_index=10, slot_type=IOLinkWirelessSlotType.UPLINK, track_id=1, device_slot=0)

        # Invalid track ID < 1 or > 5
        with pytest.raises(TrackAllocationError, match="Track ID"):
            IOLinkWirelessSubframe(subframe_index=0, slot_type=IOLinkWirelessSlotType.UPLINK, track_id=0, device_slot=0)

        with pytest.raises(TrackAllocationError, match="Track ID"):
            IOLinkWirelessSubframe(subframe_index=0, slot_type=IOLinkWirelessSlotType.UPLINK, track_id=6, device_slot=0)

        # Invalid device slot < 0 or >= 8
        with pytest.raises(TrackAllocationError, match="Device slot"):
            IOLinkWirelessSubframe(subframe_index=0, slot_type=IOLinkWirelessSlotType.UPLINK, track_id=1, device_slot=-1)

        with pytest.raises(TrackAllocationError, match="Device slot"):
            IOLinkWirelessSubframe(subframe_index=0, slot_type=IOLinkWirelessSlotType.UPLINK, track_id=1, device_slot=8)

        # Invalid channel offset < 0 or >= 80
        with pytest.raises(CoexistenceError, match="Channel offset"):
            IOLinkWirelessSubframe(subframe_index=0, slot_type=IOLinkWirelessSlotType.UPLINK, track_id=1, device_slot=0, channel_offset=80)

    def test_w_cycle_schedule_slot_allocation_and_retrieval(self) -> None:
        """Verify scheduling subframes across W-Cycle and retrieval by index."""
        schedule = WCycleSchedule()
        sf0 = IOLinkWirelessSubframe(subframe_index=0, slot_type=IOLinkWirelessSlotType.DOWNLINK, track_id=1, device_slot=0)
        sf1 = IOLinkWirelessSubframe(subframe_index=1, slot_type=IOLinkWirelessSlotType.UPLINK, track_id=1, device_slot=0)
        sf2 = IOLinkWirelessSubframe(subframe_index=1, slot_type=IOLinkWirelessSlotType.UPLINK, track_id=2, device_slot=0)

        schedule.add_subframe(sf0)
        schedule.add_subframe(sf1)
        schedule.add_subframe(sf2)

        assert len(schedule.subframes) == 3
        subframes_0 = schedule.get_subframes_for_index(0)
        assert len(subframes_0) == 1
        assert subframes_0[0] == sf0

        subframes_1 = schedule.get_subframes_for_index(1)
        assert len(subframes_1) == 2

        # Remove subframe
        removed = schedule.remove_subframe(subframe_index=1, track_id=1, device_slot=0)
        assert removed is True
        assert len(schedule.get_subframes_for_index(1)) == 1

        # Clear
        schedule.clear()
        assert len(schedule.subframes) == 0

    def test_w_cycle_schedule_collision_detection(self) -> None:
        """Verify scheduling collision detection for duplicate slot on same track."""
        schedule = WCycleSchedule()
        sf_a = IOLinkWirelessSubframe(subframe_index=3, slot_type=IOLinkWirelessSlotType.UPLINK, track_id=2, device_slot=4)
        schedule.add_subframe(sf_a)

        # Duplicate slot on same subframe index and track
        sf_conflict = IOLinkWirelessSubframe(subframe_index=3, slot_type=IOLinkWirelessSlotType.UPLINK, track_id=2, device_slot=4)
        with pytest.raises(TrackAllocationError, match="Slot collision"):
            schedule.add_subframe(sf_conflict)

    def test_frequency_hopping_calculation(self) -> None:
        """Verify active physical channel calculation within 0..79 range."""
        for cycle in range(50):
            for track in range(1, 6):
                ch = calc_iolink_wireless_hopping_channel(cycle_counter=cycle, track_id=track)
                assert 0 <= ch < NUM_CHANNELS

    def test_frequency_hopping_sequence_determinism_and_orthogonality(self) -> None:
        """Verify deterministic sequence generation and cross-track orthogonality."""
        seq_t1_a = generate_track_hopping_sequence(track_id=1, seed=0x10A)
        seq_t1_b = generate_track_hopping_sequence(track_id=1, seed=0x10A)
        assert seq_t1_a == seq_t1_b
        assert len(seq_t1_a) == NUM_CHANNELS
        assert set(seq_t1_a) == set(range(NUM_CHANNELS))

        # Different track gives different sequence (orthogonal hopping)
        seq_t2 = generate_track_hopping_sequence(track_id=2, seed=0x10A)
        assert seq_t1_a != seq_t2
        assert len(seq_t2) == NUM_CHANNELS
        assert set(seq_t2) == set(range(NUM_CHANNELS))

    def test_frequency_hopping_with_channel_blacklisting(self) -> None:
        """Verify frequency hopping avoids blacklisted channels."""
        blacklisted = {0, 1, 2, 3, 4, 10, 20, 30, 40, 50, 60, 70}
        seq = generate_track_hopping_sequence(track_id=1, blacklisted_channels=blacklisted)
        assert len(seq) == NUM_CHANNELS - len(blacklisted)
        assert all(ch not in blacklisted for ch in seq)

        for cycle in range(30):
            ch = calc_iolink_wireless_hopping_channel(cycle_counter=cycle, track_id=1, blacklisted_channels=blacklisted)
            assert ch not in blacklisted


# ============================================================================
# Section 4: Multi-Track Allocation (5 Tracks, 40 Devices) & Coexistence
# ============================================================================


class TestSection4MultiTrackAndCoexistence:
    """Tests for 5-track allocation (up to 40 devices) and Wi-Fi coexistence blacklisting."""

    def test_multi_track_capacity_40_devices(self) -> None:
        """Verify manager supports exactly 40 devices across 5 tracks."""
        mgr = IOLinkWirelessMultiTrackManager(max_tracks=5, devices_per_track=8)
        dev_id = 1
        for track in range(1, 6):
            for slot in range(8):
                dev = mgr.register_device(device_id=dev_id, track_id=track, device_slot=slot, rssi_dbm=-65.0)
                assert dev.device_id == dev_id
                assert dev.track_id == track
                assert dev.device_slot == slot
                dev_id += 1

        assert mgr.total_devices == 40
        assert mgr.online_devices == 40
        assert mgr.active_tracks_mask == 0x1F  # Bits 0..4 set

    def test_41st_device_capacity_exceeded_raises(self) -> None:
        """Verify registering 41st device raises TrackAllocationError."""
        mgr = IOLinkWirelessMultiTrackManager()
        dev_id = 1
        for track in range(1, 6):
            for slot in range(8):
                mgr.register_device(device_id=dev_id, track_id=track, device_slot=slot)
                dev_id += 1

        with pytest.raises(TrackAllocationError, match="Maximum capacity"):
            mgr.register_device(device_id=99, track_id=1, device_slot=0)

    def test_duplicate_slot_allocation_raises(self) -> None:
        """Verify registering a device in an occupied slot raises TrackAllocationError."""
        mgr = IOLinkWirelessMultiTrackManager()
        mgr.register_device(device_id=1, track_id=1, device_slot=2)

        with pytest.raises(TrackAllocationError, match="already occupied"):
            mgr.register_device(device_id=2, track_id=1, device_slot=2)

    def test_invalid_track_or_slot_raises(self) -> None:
        """Verify out-of-range track ID or device slot raises TrackAllocationError."""
        mgr = IOLinkWirelessMultiTrackManager()
        with pytest.raises(TrackAllocationError, match="Invalid track ID"):
            mgr.register_device(device_id=1, track_id=0, device_slot=0)

        with pytest.raises(TrackAllocationError, match="Invalid track ID"):
            mgr.register_device(device_id=1, track_id=6, device_slot=0)

        with pytest.raises(TrackAllocationError, match="Invalid device slot"):
            mgr.register_device(device_id=1, track_id=1, device_slot=-1)

        with pytest.raises(TrackAllocationError, match="Invalid device slot"):
            mgr.register_device(device_id=1, track_id=1, device_slot=8)

    def test_active_tracks_bitmask(self) -> None:
        """Verify active tracks bitmask reflects active devices per track."""
        mgr = IOLinkWirelessMultiTrackManager()
        assert mgr.active_tracks_mask == 0x00

        mgr.register_device(device_id=1, track_id=1, device_slot=0)
        assert mgr.active_tracks_mask == 0x01  # Bit 0

        mgr.register_device(device_id=2, track_id=3, device_slot=0)
        assert mgr.active_tracks_mask == 0x05  # Bit 0 and Bit 2

        mgr.register_device(device_id=3, track_id=5, device_slot=0)
        assert mgr.active_tracks_mask == 0x15  # Bit 0, 2, 4

    def test_wifi_coexistence_blacklisting(self) -> None:
        """Verify Wi-Fi channel blacklisting maps to correct 2.4 GHz physical channels."""
        bl_1 = get_wifi_coexistence_blacklist([1])
        assert set(bl_1) == set(range(1, 22))

        bl_6 = get_wifi_coexistence_blacklist([6])
        assert set(bl_6) == set(range(26, 47))

        bl_11 = get_wifi_coexistence_blacklist([11])
        assert set(bl_11) == set(range(51, 72))

        bl_all = get_wifi_coexistence_blacklist([1, 6, 11])
        assert len(bl_all) == 21 * 3
        assert bl_1.issubset(bl_all)

        with pytest.raises(CoexistenceError, match="Unsupported Wi-Fi channel"):
            get_wifi_coexistence_blacklist([2])

    def test_all_channels_blacklisted_raises(self) -> None:
        """Verify blacklisting all 80 channels raises CoexistenceError."""
        all_channels = set(range(80))
        with pytest.raises(CoexistenceError, match="All frequency channels are blacklisted"):
            generate_track_hopping_sequence(track_id=1, blacklisted_channels=all_channels)

    def test_device_watchdog_inactivity(self) -> None:
        """Verify check_watchdogs marks timed out devices offline."""
        mgr = IOLinkWirelessMultiTrackManager()
        t0 = time.time()
        mgr.register_device(device_id=1, track_id=1, device_slot=0, now=t0 - 40.0)
        mgr.register_device(device_id=2, track_id=1, device_slot=1, now=t0)

        offline = mgr.check_watchdogs(timeout_s=30.0, current_time=t0)
        assert len(offline) == 1
        assert offline[0].device_id == 1
        assert mgr.online_devices == 1
        assert mgr.total_devices == 2

    def test_unregister_device_and_clear(self) -> None:
        """Verify unregistering individual devices and clearing manager."""
        mgr = IOLinkWirelessMultiTrackManager()
        mgr.register_device(device_id=1, track_id=1, device_slot=0)
        mgr.register_device(device_id=2, track_id=2, device_slot=0)

        assert mgr.total_devices == 2
        assert mgr.unregister_device(track_id=1, device_slot=0) is True
        assert mgr.total_devices == 1
        assert mgr.get_device_by_slot(track_id=1, device_slot=0) is None

        mgr.clear()
        assert mgr.total_devices == 0


# ============================================================================
# Section 5: Process Data (PD) & On-Request Data (OD) Framing & Scaling
# ============================================================================


class TestSection5ProcessDataAndOnRequestData:
    """Tests for cyclic Process Data (PD) and acyclic On-Request Data (OD) framing, CRC-16, and scaling."""

    def test_crc16_calculation_and_verification(self) -> None:
        """Verify CRC-16-CCITT calculation and tamper detection."""
        data = b"\x01\x05\x42\x36\x66\x66\x41\x44\xCC\xCD"
        crc = calc_crc16(data)
        assert 0 <= crc <= 0xFFFF
        assert verify_crc16(data, crc) is True

        corrupt_crc = crc ^ 0x0001
        assert verify_crc16(data, corrupt_crc) is False

    def test_process_data_encode_decode_roundtrip(self) -> None:
        """Verify Process Data encoding and decoding roundtrip."""
        raw = encode_process_data(status=0x01, pv=125.4, sv=23.7, digital_inputs=0x0B)
        assert len(raw) == 12

        payload = decode_process_data(raw, verify_crc=True)
        assert payload.status_byte == 0x01
        assert payload.digital_inputs == 0x0B
        assert math.isclose(payload.primary_pv, 125.4, abs_tol=0.01)
        assert math.isclose(payload.secondary_sv, 23.7, abs_tol=0.01)

    def test_process_data_tampered_crc_raises_crc_integrity_error(self) -> None:
        """Verify corrupted Process Data frame raises CRCIntegrityError."""
        raw = bytearray(encode_process_data(status=0x01, pv=50.0, sv=10.0))
        raw[2] ^= 0xFF  # Corrupt PV byte
        with pytest.raises(CRCIntegrityError, match="CRC-16 verification failed"):
            decode_process_data(bytes(raw), verify_crc=True)

    def test_process_data_truncation_raises(self) -> None:
        """Verify short Process Data payload raises ProcessDataDecodeError."""
        with pytest.raises(ProcessDataDecodeError, match="too short"):
            decode_process_data(b"\x01\x00\x00")

    def test_scale_pv_to_int16(self) -> None:
        """Verify scaling float values to INT16 engineering units with clamping."""
        assert scale_pv_to_int16(125.4, scale_factor=10.0) == 1254
        assert scale_pv_to_int16(250.0, scale_factor=10.0) == 2500
        assert scale_pv_to_int16(5000.0, scale_factor=10.0) == 32767   # Clamped max
        assert scale_pv_to_int16(-5000.0, scale_factor=10.0) == -32768  # Clamped min

    def test_od_request_response_roundtrip(self) -> None:
        """Verify acyclic On-Request Data (OD) request and response encoding/decoding."""
        raw_req = encode_od_request(is_write=True, index=0x0012, subindex=0x01, data=b"\xCA\xFE")
        assert len(raw_req) == 6
        req = decode_od_request(raw_req)
        assert req.is_write is True
        assert req.index == 0x0012
        assert req.subindex == 0x01
        assert req.data == b"\xCA\xFE"

        raw_resp = encode_od_response(status=0x00, index=0x0012, subindex=0x01, data=b"\x01\x02\x03")
        resp = decode_od_response(raw_resp)
        assert resp.status == 0x00
        assert resp.index == 0x0012
        assert resp.subindex == 0x01
        assert resp.data == b"\x01\x02\x03"

    def test_od_truncation_raises(self) -> None:
        """Verify truncated OD frames raise OnRequestDataError."""
        with pytest.raises(OnRequestDataError, match="OD request too short"):
            decode_od_request(b"\x01\x02")

        with pytest.raises(OnRequestDataError, match="OD response too short"):
            decode_od_response(b"\x00\x01")


# ============================================================================
# Section 6: Process Safety Trips (0x9E01..0x9E04) & Horner Coils (%M219, %M220)
# ============================================================================


class TestSection6ProcessSafetyTrips:
    """Tests for safety trips 0x9E01..0x9E04 asserting %M219/%M220 and diagnostic codes."""

    def test_diagnostic_codes_and_status_bits_values(self) -> None:
        """Verify enumeration values and bitmasks."""
        assert int(IOLinkWirelessDiagnosticCode.OK) == 0x0000
        assert int(IOLinkWirelessDiagnosticCode.W_CYCLE_TIMEOUT_TRIP) == 0x9E01
        assert int(IOLinkWirelessDiagnosticCode.RF_INTERFERENCE_PER_ALARM) == 0x9E02
        assert int(IOLinkWirelessDiagnosticCode.TRACK_COLLISION_ALARM) == 0x9E03
        assert int(IOLinkWirelessDiagnosticCode.DEVICE_DISCONNECT_TRIP) == 0x9E04

        assert int(IOLinkWirelessStatusBits.NETWORK_ACTIVE) == 0x0001
        assert int(IOLinkWirelessStatusBits.W_CYCLE_SYNCHRONIZED) == 0x0002
        assert int(IOLinkWirelessStatusBits.FREQUENCY_HOPPING_ACTIVE) == 0x0004
        assert int(IOLinkWirelessStatusBits.MULTI_TRACK_ACTIVE) == 0x0008
        assert int(IOLinkWirelessStatusBits.W_CYCLE_TIMEOUT_TRIP) == 0x0010
        assert int(IOLinkWirelessStatusBits.RF_INTERFERENCE_PER_ALARM) == 0x0020
        assert int(IOLinkWirelessStatusBits.TRACK_COLLISION_ALARM) == 0x0040
        assert int(IOLinkWirelessStatusBits.DEVICE_DISCONNECT_TRIP) == 0x0080

    def test_w_cycle_timeout_trip_0x9E01(self, wireless_master: IOLinkWirelessMaster) -> None:
        """Verify 0x9E01 W-Cycle timeout trip asserts %M220 and clears %M219."""
        wm = wireless_master
        wm.register_device(device_id=1, track_id=1, device_slot=0)
        wm._sync_registers()
        assert wm.reg_table.read_bit("%M219") is True
        assert wm.reg_table.read_bit("%M220") is False

        tripped = wm.check_w_cycle_watchdog(simulated_elapsed_s=W_CYCLE_TIMEOUT_S + 2.0)
        assert tripped is True
        assert wm.reg_table.read_uword("%R947") == int(IOLinkWirelessDiagnosticCode.W_CYCLE_TIMEOUT_TRIP)
        assert wm.reg_table.read_bit("%M220") is True
        assert wm.reg_table.read_bit("%M219") is False
        assert bool(wm.reg_table.read_uword("%R940") & IOLinkWirelessStatusBits.W_CYCLE_TIMEOUT_TRIP) is True

    def test_rf_interference_per_alarm_0x9E02(self, wireless_master: IOLinkWirelessMaster) -> None:
        """Verify 0x9E02 RF interference / CRC error sets status bit and diagnostic code."""
        wm = wireless_master
        wm.register_device(device_id=1, track_id=1, device_slot=0)

        # Corrupt CRC frame
        bad_frame = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xDE\xAD"
        ok = wm.process_device_process_data(track_id=1, device_slot=0, raw_frame=bad_frame)
        assert ok is False
        assert wm.reg_table.read_uword("%R947") == int(IOLinkWirelessDiagnosticCode.RF_INTERFERENCE_PER_ALARM)
        assert bool(wm.reg_table.read_uword("%R940") & IOLinkWirelessStatusBits.RF_INTERFERENCE_PER_ALARM) is True

    def test_track_collision_alarm_0x9E03(self, wireless_master: IOLinkWirelessMaster) -> None:
        """Verify 0x9E03 Multi-Track Collision Alarm sets status bit and diagnostic code."""
        wm = wireless_master
        wm.trigger_track_collision(track_id=1, device_slot=0)
        assert wm.reg_table.read_uword("%R947") == int(IOLinkWirelessDiagnosticCode.TRACK_COLLISION_ALARM)
        assert bool(wm.reg_table.read_uword("%R940") & IOLinkWirelessStatusBits.TRACK_COLLISION_ALARM) is True

    def test_device_disconnect_trip_0x9E04(self, wireless_master: IOLinkWirelessMaster) -> None:
        """Verify 0x9E04 Device Disconnect Trip asserts %M220 and clears %M219."""
        wm = wireless_master
        wm.register_device(device_id=1, track_id=1, device_slot=0)
        wm._sync_registers()
        assert wm.reg_table.read_bit("%M219") is True

        tripped = wm.check_devices_watchdog(simulated_elapsed_s=DEFAULT_WATCHDOG_TIMEOUT_S + 5.0)
        assert tripped is True
        assert wm.reg_table.read_uword("%R947") == int(IOLinkWirelessDiagnosticCode.DEVICE_DISCONNECT_TRIP)
        assert wm.reg_table.read_bit("%M220") is True
        assert wm.reg_table.read_bit("%M219") is False
        assert bool(wm.reg_table.read_uword("%R940") & IOLinkWirelessStatusBits.DEVICE_DISCONNECT_TRIP) is True

    def test_manual_safety_trip_dispatch(self, wireless_master: IOLinkWirelessMaster) -> None:
        """Verify trigger_safety_trip dispatches any valid code correctly."""
        wm = wireless_master
        wm.trigger_safety_trip(IOLinkWirelessDiagnosticCode.W_CYCLE_TIMEOUT_TRIP)
        assert wm.reg_table.read_bit("%M220") is True
        assert wm.reg_table.read_bit("%M219") is False

    def test_reset_fault_trip_recovery(self, wireless_master: IOLinkWirelessMaster) -> None:
        """Verify reset_fault_trip clears alarms and restores healthy coils."""
        wm = wireless_master
        wm.register_device(device_id=1, track_id=1, device_slot=0)
        wm.check_w_cycle_watchdog(simulated_elapsed_s=10.0)
        assert wm.reg_table.read_bit("%M220") is True

        wm.reset_fault_trip()
        assert wm.diagnostic_code == IOLinkWirelessDiagnosticCode.OK
        assert wm.reg_table.read_uword("%R947") == 0x0000
        assert wm.reg_table.read_bit("%M220") is False
        assert wm.reg_table.read_bit("%M219") is True


# ============================================================================
# Section 7: Horner OCS Memory Space Integration (%R940..%R947, %M219..%M220)
# ============================================================================


class TestSection7HornerOCSMemoryIntegration:
    """Tests for Horner OCS register space synchronization (%R940..%R947, %M219..%M220)."""

    def test_initial_register_space_state(self, wireless_master: IOLinkWirelessMaster) -> None:
        """Verify initial register state matches Horner OCS specifications."""
        wm = wireless_master
        assert wm.reg_table.read_word("%R941") == 0
        assert wm.reg_table.read_word("%R942") == 0
        assert wm.reg_table.read_word("%R943") == 0
        assert wm.reg_table.read_word("%R944") == 0
        assert wm.reg_table.read_word("%R945") == 0
        assert wm.reg_table.read_word("%R946") == 0
        assert wm.reg_table.read_uword("%R947") == 0x0000
        assert wm.reg_table.read_bit("%M219") is True
        assert wm.reg_table.read_bit("%M220") is False

    def test_process_data_register_sync(self, wireless_master: IOLinkWirelessMaster) -> None:
        """Verify cyclic Process Data updates %R943 (PV x10), %R944 (SV x10), and %R941."""
        wm = wireless_master
        wm.register_device(device_id=1, track_id=1, device_slot=0)

        raw_pd = encode_process_data(status=0x01, pv=88.5, sv=14.2)
        ok = wm.process_device_process_data(track_id=1, device_slot=0, raw_frame=raw_pd)
        assert ok is True

        assert wm.reg_table.read_word("%R941") == 1
        assert wm.reg_table.read_uword("%R942") == 0x0001  # Track 1
        assert wm.reg_table.read_word("%R943") == 885   # 88.5 * 10
        assert wm.reg_table.read_word("%R944") == 142   # 14.2 * 10
        assert wm.reg_table.read_bit("%M219") is True
        assert wm.reg_table.read_bit("%M220") is False

    def test_clamped_signed_int16_registers(self, wireless_master: IOLinkWirelessMaster) -> None:
        """Verify scaled PV and SV values clamp cleanly to signed 16-bit range."""
        wm = wireless_master
        wm.primary_pv = 5000.0   # 50000 -> clamps to 32767
        wm.secondary_sv = -5000.0  # -50000 -> clamps to -32768
        wm._sync_registers()

        assert wm.reg_table.read_word("%R943") == 32767
        assert wm.reg_table.read_word("%R944") == -32768

    def test_average_rssi_register_sync(self, wireless_master: IOLinkWirelessMaster) -> None:
        """Verify %R945 reflects average RSSI in signed dBm."""
        wm = wireless_master
        wm.register_device(device_id=1, track_id=1, device_slot=0, rssi_dbm=-60.0)
        wm.register_device(device_id=2, track_id=2, device_slot=0, rssi_dbm=-70.0)
        wm._sync_registers()

        assert wm.reg_table.read_word("%R945") == -65

    def test_w_cycle_counter_sync(self, wireless_master: IOLinkWirelessMaster) -> None:
        """Verify %R946 tracks W-Cycle execution."""
        wm = wireless_master
        wm.step_w_cycle(cycles=25)
        assert wm.reg_table.read_word("%R946") == 25

    def test_od_command_execution(self, wireless_master: IOLinkWirelessMaster) -> None:
        """Verify acyclic OD parameter commands."""
        wm = wireless_master
        wm.register_device(device_id=1, track_id=1, device_slot=0)

        req = IOLinkWirelessODRequest(is_write=False, index=0x1000, subindex=0x01)
        resp = wm.execute_od_command(track_id=1, device_slot=0, request=req)
        assert resp.status == 0x00
        assert resp.index == 0x1000

        # Unregistered device slot returns error 0x8011
        resp_err = wm.execute_od_command(track_id=1, device_slot=7, request=req)
        assert resp_err.status == 0x8011


# ============================================================================
# Section 8: 9-Stage Verification Suite Integration & Evidence Persistence
# ============================================================================


class TestSection8VerificationSuiteIntegration:
    """Tests for the complete 9-stage verification suite and evidence persistence."""

    def test_run_iolink_wireless_verification_success(self) -> None:
        """Verify the 9-stage verification returns a clean SUCCESS status."""
        result = run_iolink_wireless_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None
        assert result["data"]["checks_passed"] == 9
        assert result["data"]["total_checks"] == 9
        assert len(result["data"]["tests"]) == 9

    def test_run_iolink_wireless_verification_writes_evidence(self, tmp_path: Path) -> None:
        """Verify verification writes valid JSON evidence matching contract schema."""
        evidence_file = tmp_path / "iolink_wireless_evidence.json"
        result = run_iolink_wireless_verification(evidence_path=str(evidence_file))

        assert evidence_file.exists()
        with open(evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["status"] == "success"
        assert data["data"]["work_package"] == "W133"
        assert data["data"]["gate"] == "Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation"
        assert data["data"]["component"] == "Industrial IO-Link Wireless (IEC 61131-9 Extension) Protocol Engine & Multi-Track Master"
        assert data["data"]["checks_passed"] == 9
        assert len(data["data"]["tests"]) == 9
        assert data["data"]["register_map"]["status_word"] == "%R940"
        assert data["data"]["register_map"]["active_devices_count"] == "%R941"
        assert data["data"]["register_map"]["active_tracks_mask"] == "%R942"
        assert data["data"]["register_map"]["primary_variable_pv_scaled"] == "%R943"
        assert data["data"]["register_map"]["network_active_coil"] == "%M219"
        assert data["data"]["register_map"]["fault_trip_coil"] == "%M220"

    def test_evidence_metrics_schema(self) -> None:
        """Verify evidence metrics dictionary has all expected fields."""
        result = run_iolink_wireless_verification()
        metrics = result["data"]["metrics"]
        assert metrics["max_tracks"] == 5
        assert metrics["devices_per_track"] == 8
        assert metrics["max_devices"] == 40
        assert metrics["w_cycle_duration_ms"] == 5
        assert metrics["subframes_per_cycle"] == 10
        assert metrics["num_channels"] == 80
