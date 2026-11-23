"""Comprehensive Unit Test Suite for ISA-18.2 Alarm Management & Event Historian.

Work Package: W028 (Gate G8 / Alarming & Historian)
Classification: PRODUCTION / TESTED_MOCK

Tests:
1. ISA-18.2 state transitions:
   - NORMAL -> UNACKNOWLEDGED (trip)
   - UNACKNOWLEDGED -> ACKNOWLEDGED (acknowledge)
   - ACKNOWLEDGED -> NORMAL (clear)
   - UNACKNOWLEDGED -> RTN_UNACK (clear before ack)
   - RTN_UNACK -> NORMAL (acknowledge after clear)
   - RTN_UNACK -> UNACKNOWLEDGED (re-trip before ack)
   - Shelving from any state & unshelving (active vs normal conditions)
   - Shelve auto-expiration
   - Batch acknowledgement (acknowledge_all)
2. Scan cycle register monitoring:
   - Discrete bits (%M, %I, %Q) and bit-slices (%R.x) with RegisterTable
   - On-delay debounce timing (delay_ms)
   - Analog thresholds and deadband hysteresis (high alarms & low alarms)
3. Circular event buffer:
   - Default capacity (5,000)
   - FIFO overflow wrapping and event retention
   - Microsecond timestamping accuracy
4. Priority filtering and summaries:
   - Severity filtering (LOW, MEDIUM, HIGH, CRITICAL)
   - Unacknowledged counts and active summaries
5. Deterministic JSON export:
   - Event log, state snapshot, summary, and full audit bundle
   - Byte-level determinism and round-trip JSON deserialization
6. Validation and boundary cases:
   - Duplicate tags, non-existent tags, negative deadbands/delays
"""

import json
from pathlib import Path
import re
import time
import pytest
from pydantic import ValidationError

from jev_cscape.alarming.historian import (
    AlarmDefinition,
    AlarmEvent,
    AlarmManager,
    AlarmRecord,
    AlarmSeverity,
    AlarmState,
    CircularEventBuffer,
    format_utc_microsecond,
)
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


class TestISA182StateTransitions:
    """Validate strict ANSI/ISA-18.2-2016 alarm state machine lifecycle."""

    @pytest.fixture
    def manager(self) -> AlarmManager:
        mgr = AlarmManager()
        mgr.register_alarm(
            AlarmDefinition(
                tag="PAL_101",
                description="Pump Low Pressure Alarm",
                bound_bit="%M1",
                severity=AlarmSeverity.HIGH,
            )
        )
        return mgr

    def test_normal_to_unacknowledged_trip(self, manager: AlarmManager):
        assert manager.get_state("PAL_101") == AlarmState.NORMAL
        evt = manager.trip("PAL_101", value=True, message="Low pressure detected")
        assert evt is not None
        assert manager.get_state("PAL_101") == AlarmState.UNACKNOWLEDGED
        assert evt.state_transition == "NORMAL -> UNACKNOWLEDGED"
        assert evt.tag == "PAL_101"
        assert manager.is_active("PAL_101") is True
        assert manager.is_unacknowledged("PAL_101") is True

    def test_unacknowledged_to_acknowledged(self, manager: AlarmManager):
        manager.trip("PAL_101")
        evt = manager.acknowledge("PAL_101", operator_id="OP_ALICE", note="Investigating pump")
        assert evt is not None
        assert manager.get_state("PAL_101") == AlarmState.ACKNOWLEDGED
        assert evt.state_transition == "UNACKNOWLEDGED -> ACKNOWLEDGED"
        assert manager.is_active("PAL_101") is True
        assert manager.is_unacknowledged("PAL_101") is False
        record = manager.get_record("PAL_101")
        assert record.acknowledged_by == "OP_ALICE"

    def test_acknowledged_to_normal_clear(self, manager: AlarmManager):
        manager.trip("PAL_101")
        manager.acknowledge("PAL_101", operator_id="OP_BOB")
        evt = manager.clear("PAL_101", value=False)
        assert evt is not None
        assert manager.get_state("PAL_101") == AlarmState.NORMAL
        assert evt.state_transition == "ACKNOWLEDGED -> NORMAL"
        assert manager.is_active("PAL_101") is False

    def test_unacknowledged_to_rtn_unack_clear(self, manager: AlarmManager):
        # Process transiently trips and clears before operator acknowledges
        manager.trip("PAL_101")
        evt = manager.clear("PAL_101", value=False)
        assert evt is not None
        assert manager.get_state("PAL_101") == AlarmState.RTN_UNACK
        assert evt.state_transition == "UNACKNOWLEDGED -> RTN_UNACK"
        assert manager.is_active("PAL_101") is True
        assert manager.is_unacknowledged("PAL_101") is True

    def test_rtn_unack_to_normal_acknowledge(self, manager: AlarmManager):
        manager.trip("PAL_101")
        manager.clear("PAL_101")
        assert manager.get_state("PAL_101") == AlarmState.RTN_UNACK
        evt = manager.acknowledge("PAL_101", operator_id="OP_CHARLIE")
        assert evt is not None
        assert manager.get_state("PAL_101") == AlarmState.NORMAL
        assert evt.state_transition == "RTN_UNACK -> NORMAL"
        assert manager.is_active("PAL_101") is False

    def test_rtn_unack_to_unacknowledged_retrip(self, manager: AlarmManager):
        manager.trip("PAL_101")
        manager.clear("PAL_101")
        assert manager.get_state("PAL_101") == AlarmState.RTN_UNACK
        # Process condition re-enters abnormal condition before acknowledgement
        evt = manager.trip("PAL_101", value=True, message="Low pressure re-tripped")
        assert evt is not None
        assert manager.get_state("PAL_101") == AlarmState.UNACKNOWLEDGED
        assert evt.state_transition == "RTN_UNACK -> UNACKNOWLEDGED"

    def test_shelving_and_unshelving_normal_condition(self, manager: AlarmManager):
        manager.trip("PAL_101")
        assert manager.get_state("PAL_101") == AlarmState.UNACKNOWLEDGED

        # Shelve alarm
        evt_shelve = manager.shelve("PAL_101", reason="Scheduled maintenance", duration_s=3600.0)
        assert evt_shelve is not None
        assert manager.get_state("PAL_101") == AlarmState.SHELVED
        assert evt_shelve.state_transition == "UNACKNOWLEDGED -> SHELVED"
        assert manager.shelved_count == 1

        # While shelved, abnormal condition clears
        manager.clear("PAL_101")
        assert manager.get_state("PAL_101") == AlarmState.SHELVED

        # Unshelve when physical condition is normal -> transitions to NORMAL
        evt_unshelve = manager.unshelve("PAL_101")
        assert evt_unshelve is not None
        assert manager.get_state("PAL_101") == AlarmState.NORMAL
        assert evt_unshelve.state_transition == "SHELVED -> NORMAL"

    def test_shelving_and_unshelving_active_condition(self, manager: AlarmManager):
        manager.shelve("PAL_101", reason="Pre-maintenance")
        assert manager.get_state("PAL_101") == AlarmState.SHELVED

        # Trip while shelved: state remains SHELVED
        manager.trip("PAL_101")
        assert manager.get_state("PAL_101") == AlarmState.SHELVED

        # Unshelve while active: transitions to UNACKNOWLEDGED
        evt_unshelve = manager.unshelve("PAL_101")
        assert evt_unshelve is not None
        assert manager.get_state("PAL_101") == AlarmState.UNACKNOWLEDGED
        assert evt_unshelve.state_transition == "SHELVED -> UNACKNOWLEDGED"

    def test_shelving_auto_expiration(self, manager: AlarmManager):
        manager.shelve("PAL_101", reason="Quick test", duration_s=0.005)
        assert manager.get_state("PAL_101") == AlarmState.SHELVED
        time.sleep(0.01)  # Allow duration to expire
        # evaluate_cycle will trigger auto-unshelve
        events = manager.evaluate_cycle(values={"%M1": False}, dt_ms=10.0)
        assert len(events) >= 1
        assert manager.get_state("PAL_101") == AlarmState.NORMAL

    def test_acknowledge_all(self, manager: AlarmManager):
        manager.register_alarm(AlarmDefinition(tag="TAH_201", bound_bit="%M2", severity=AlarmSeverity.CRITICAL))
        manager.register_alarm(AlarmDefinition(tag="LAH_301", bound_bit="%M3", severity=AlarmSeverity.MEDIUM))

        manager.trip("PAL_101")
        manager.trip("TAH_201")
        manager.trip("LAH_301")
        manager.clear("LAH_301")  # LAH_301 becomes RTN_UNACK

        assert manager.unacknowledged_count == 3
        events = manager.acknowledge_all(operator_id="SUPERVISOR")
        assert len(events) == 3
        assert manager.unacknowledged_count == 0
        assert manager.get_state("PAL_101") == AlarmState.ACKNOWLEDGED
        assert manager.get_state("TAH_201") == AlarmState.ACKNOWLEDGED
        assert manager.get_state("LAH_301") == AlarmState.NORMAL


class TestAlarmScanMonitoring:
    """Validate scan-cycle monitoring, Horner RegisterTable integration, debounce & deadband."""

    def test_register_table_discrete_bit_monitoring(self):
        reg_table = RegisterTable()
        reg_table.privilege_mode = PrivilegeMode.SYSTEM
        reg_table.write_bit("%M1", False)

        mgr = AlarmManager()
        mgr.register_alarm(
            AlarmDefinition(
                tag="PUMP_FAULT",
                description="Pump overload trip bit",
                bound_bit="%M1",
                severity=AlarmSeverity.CRITICAL,
            )
        )

        # Scan 1: Bit is False -> remains NORMAL
        events = mgr.evaluate_cycle(register_table=reg_table, dt_ms=10.0)
        assert len(events) == 0
        assert mgr.get_state("PUMP_FAULT") == AlarmState.NORMAL

        # Scan 2: Bit turns True -> transitions to UNACKNOWLEDGED
        reg_table.write_bit("%M1", True)
        events = mgr.evaluate_cycle(register_table=reg_table, dt_ms=10.0)
        assert len(events) == 1
        assert events[0].state_transition == "NORMAL -> UNACKNOWLEDGED"
        assert mgr.get_state("PUMP_FAULT") == AlarmState.UNACKNOWLEDGED

        # Scan 3: Bit turns False -> transitions to RTN_UNACK
        reg_table.write_bit("%M1", False)
        events = mgr.evaluate_cycle(register_table=reg_table, dt_ms=10.0)
        assert len(events) == 1
        assert events[0].state_transition == "UNACKNOWLEDGED -> RTN_UNACK"
        assert mgr.get_state("PUMP_FAULT") == AlarmState.RTN_UNACK

    def test_register_table_io_channels_and_bit_slice(self):
        reg_table = RegisterTable()
        reg_table.privilege_mode = PrivilegeMode.SYSTEM
        reg_table.write_bit("%I1", False)
        reg_table.write_bit("%Q1", False)
        reg_table.write_word("%R100", 0)

        mgr = AlarmManager()
        mgr.register_alarm(AlarmDefinition(tag="INPUT_ALM", bound_bit="%I1", severity=AlarmSeverity.LOW))
        mgr.register_alarm(AlarmDefinition(tag="OUTPUT_ALM", bound_bit="%Q1", severity=AlarmSeverity.MEDIUM))
        mgr.register_alarm(AlarmDefinition(tag="SLICE_ALM", bound_bit="%R100.3", severity=AlarmSeverity.HIGH))

        # Set %I1 and bit 3 of %R100 (mask 0x0004 = 4)
        reg_table.write_bit("%I1", True)
        reg_table.write_word("%R100", 4)

        events = mgr.evaluate_cycle(register_table=reg_table, dt_ms=10.0)
        tripped_tags = {e.tag for e in events}
        assert "INPUT_ALM" in tripped_tags
        assert "SLICE_ALM" in tripped_tags
        assert "OUTPUT_ALM" not in tripped_tags

    def test_on_delay_debouncing(self):
        mgr = AlarmManager()
        mgr.register_alarm(
            AlarmDefinition(
                tag="CHAMBER_PRESSURE",
                bound_bit="%M5",
                severity=AlarmSeverity.HIGH,
                delay_ms=50.0,  # 50 ms on-delay filter
            )
        )

        # Transient glitch for 20 ms (2 cycles of 10 ms)
        mgr.evaluate_cycle(values={"%M5": True}, dt_ms=10.0)
        assert mgr.get_state("CHAMBER_PRESSURE") == AlarmState.NORMAL
        mgr.evaluate_cycle(values={"%M5": True}, dt_ms=10.0)
        assert mgr.get_state("CHAMBER_PRESSURE") == AlarmState.NORMAL

        # Noise drops back to False -> accumulator resets
        mgr.evaluate_cycle(values={"%M5": False}, dt_ms=10.0)
        assert mgr.get_state("CHAMBER_PRESSURE") == AlarmState.NORMAL
        assert mgr.get_record("CHAMBER_PRESSURE").accumulated_delay_ms == 0.0

        # Sustained trip for 50 ms (5 cycles of 10 ms)
        for i in range(4):
            mgr.evaluate_cycle(values={"%M5": True}, dt_ms=10.0)
            assert mgr.get_state("CHAMBER_PRESSURE") == AlarmState.NORMAL

        # 5th cycle completes 50 ms
        evts = mgr.evaluate_cycle(values={"%M5": True}, dt_ms=10.0)
        assert len(evts) == 1
        assert mgr.get_state("CHAMBER_PRESSURE") == AlarmState.UNACKNOWLEDGED

    def test_analog_threshold_and_deadband_hysteresis_high_alarm(self):
        mgr = AlarmManager()
        mgr.register_alarm(
            AlarmDefinition(
                tag="TANK_TEMP_HIGH",
                bound_bit="%R10",
                severity=AlarmSeverity.HIGH,
                trigger_level=100.0,
                deadband=5.0,  # Trip at >= 100, clear at < 95
                trigger_high=True,
            )
        )

        # Under threshold
        mgr.evaluate_cycle(values={"%R10": 98.0})
        assert mgr.get_state("TANK_TEMP_HIGH") == AlarmState.NORMAL

        # Reaches trigger level (101.5)
        evts = mgr.evaluate_cycle(values={"%R10": 101.5})
        assert len(evts) == 1
        assert mgr.get_state("TANK_TEMP_HIGH") == AlarmState.UNACKNOWLEDGED

        # Acknowledge alarm
        mgr.acknowledge("TANK_TEMP_HIGH")
        assert mgr.get_state("TANK_TEMP_HIGH") == AlarmState.ACKNOWLEDGED

        # Temp drops to 97.0 (below 100, but still within deadband [95.0, 100.0])
        evts = mgr.evaluate_cycle(values={"%R10": 97.0})
        assert len(evts) == 0
        assert mgr.get_state("TANK_TEMP_HIGH") == AlarmState.ACKNOWLEDGED

        # Temp drops to 94.0 (below 95.0 deadband floor) -> clears to NORMAL
        evts = mgr.evaluate_cycle(values={"%R10": 94.0})
        assert len(evts) == 1
        assert mgr.get_state("TANK_TEMP_HIGH") == AlarmState.NORMAL

    def test_analog_threshold_and_deadband_low_alarm(self):
        mgr = AlarmManager()
        mgr.register_alarm(
            AlarmDefinition(
                tag="HEADER_PRESSURE_LOW",
                bound_bit="%R20",
                severity=AlarmSeverity.CRITICAL,
                trigger_level=20.0,
                deadband=2.0,  # Trip at <= 20, clear at > 22
                trigger_high=False,
            )
        )

        mgr.evaluate_cycle(values={"%R20": 25.0})
        assert mgr.get_state("HEADER_PRESSURE_LOW") == AlarmState.NORMAL

        # Drops below 20.0
        mgr.evaluate_cycle(values={"%R20": 19.5})
        assert mgr.get_state("HEADER_PRESSURE_LOW") == AlarmState.UNACKNOWLEDGED

        # Acknowledge
        mgr.acknowledge("HEADER_PRESSURE_LOW")

        # Rises to 21.0 (above 20.0, but still <= 22.0 deadband ceiling)
        mgr.evaluate_cycle(values={"%R20": 21.0})
        assert mgr.get_state("HEADER_PRESSURE_LOW") == AlarmState.ACKNOWLEDGED

        # Rises to 23.0 -> clears to NORMAL
        mgr.evaluate_cycle(values={"%R20": 23.0})
        assert mgr.get_state("HEADER_PRESSURE_LOW") == AlarmState.NORMAL


class TestCircularEventBuffer:
    """Validate circular FIFO ring buffer overflow, microsecond timestamps, and capacity."""

    def test_default_buffer_capacity_5000(self):
        mgr = AlarmManager()
        assert mgr.buffer_stats["capacity"] == 5000
        assert mgr.buffer_stats["current_size"] == 0
        assert mgr.buffer_stats["overflow_count"] == 0

    def test_buffer_overflow_wrapping(self):
        buf = CircularEventBuffer(capacity=10)
        assert buf.capacity == 10

        # Append 25 sequential events
        for i in range(1, 26):
            evt = AlarmEvent(
                event_id=f"EVT-{i:06d}",
                tag="TEST_TAG",
                timestamp_utc=format_utc_microsecond(),
                state_transition="NORMAL -> UNACKNOWLEDGED",
                value=i,
                message=f"Event number {i}",
            )
            buf.append(evt)

        assert len(buf) == 10
        assert buf.total_recorded == 25
        assert buf.overflow_count == 15

        events = buf.to_list()
        assert len(events) == 10
        # Should contain events 16 through 25
        assert events[0].event_id == "EVT-000016"
        assert events[-1].event_id == "EVT-000025"

    def test_microsecond_timestamp_format(self):
        ts = format_utc_microsecond()
        # Regex verifying ISO 8601 with exactly 6 microsecond digits and Z suffix
        pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
        assert re.match(pattern, ts) is not None


class TestPriorityFilteringAndSummaries:
    """Validate multi-tier priority filtering, active alarms, and count breakdowns."""

    @pytest.fixture
    def populated_manager(self) -> AlarmManager:
        mgr = AlarmManager()
        mgr.register_alarm(AlarmDefinition(tag="ALM_LOW", bound_bit="%M1", severity=AlarmSeverity.LOW))
        mgr.register_alarm(AlarmDefinition(tag="ALM_MED", bound_bit="%M2", severity=AlarmSeverity.MEDIUM))
        mgr.register_alarm(AlarmDefinition(tag="ALM_HIGH", bound_bit="%M3", severity=AlarmSeverity.HIGH))
        mgr.register_alarm(AlarmDefinition(tag="ALM_CRIT", bound_bit="%M4", severity=AlarmSeverity.CRITICAL))

        # Trip all
        mgr.trip("ALM_LOW")
        mgr.trip("ALM_MED")
        mgr.trip("ALM_HIGH")
        mgr.trip("ALM_CRIT")

        # Ack High
        mgr.acknowledge("ALM_HIGH")

        # Shelve Med
        mgr.shelve("ALM_MED", reason="Muffled")

        return mgr

    def test_active_and_unacknowledged_counts(self, populated_manager: AlarmManager):
        mgr = populated_manager
        assert mgr.total_registered == 4
        assert mgr.active_count == 4
        # Unacknowledged are ALM_LOW and ALM_CRIT (ALM_HIGH is ACK, ALM_MED is SHELVED)
        assert mgr.unacknowledged_count == 2
        assert mgr.acknowledged_count == 1
        assert mgr.shelved_count == 1
        assert mgr.normal_count == 0

    def test_priority_filtering_by_min_severity(self, populated_manager: AlarmManager):
        mgr = populated_manager
        # Filter active alarms with severity >= HIGH (HIGH and CRITICAL)
        high_plus = mgr.get_active_alarms(min_severity=AlarmSeverity.HIGH)
        tags = {r.definition.tag for r in high_plus}
        assert tags == {"ALM_HIGH", "ALM_CRIT"}

        # Filter unacknowledged alarms with severity >= HIGH (CRITICAL only, since HIGH is ACK)
        unack_high_plus = mgr.get_unacknowledged_alarms(min_severity=AlarmSeverity.HIGH)
        assert len(unack_high_plus) == 1
        assert unack_high_plus[0].definition.tag == "ALM_CRIT"

    def test_summary_dictionary_breakdown(self, populated_manager: AlarmManager):
        summary = populated_manager.get_summary()
        assert summary["total_registered"] == 4
        assert summary["active_count"] == 4
        assert summary["unacknowledged_count"] == 2
        assert summary["counts_by_severity"]["CRITICAL"] == 1
        assert summary["counts_by_severity"]["HIGH"] == 1
        assert summary["counts_by_severity"]["MEDIUM"] == 1
        assert summary["counts_by_severity"]["LOW"] == 1
        assert summary["counts_by_state"]["UNACKNOWLEDGED"] == 2
        assert summary["counts_by_state"]["ACKNOWLEDGED"] == 1
        assert summary["counts_by_state"]["SHELVED"] == 1


class TestDeterministicJSONExport:
    """Validate deterministic formatting, round-trip serialization, and file export."""

    @pytest.fixture
    def manager_with_history(self) -> AlarmManager:
        mgr = AlarmManager()
        mgr.register_alarm(
            AlarmDefinition(
                tag="PRESS_HI",
                description="High Pressure",
                bound_bit="%M10",
                severity=AlarmSeverity.HIGH,
            )
        )
        mgr.register_alarm(
            AlarmDefinition(
                tag="TEMP_HI",
                description="High Temperature",
                bound_bit="%M20",
                severity=AlarmSeverity.CRITICAL,
            )
        )

        mgr.trip("PRESS_HI", value=True, timestamp_utc="2026-10-02T12:00:00.000000Z")
        mgr.acknowledge("PRESS_HI", operator_id="ADMIN", timestamp_utc="2026-10-02T12:01:00.000000Z")
        mgr.trip("TEMP_HI", value=True, timestamp_utc="2026-10-02T12:02:00.000000Z")
        return mgr

    def test_export_events_json(self, manager_with_history: AlarmManager, tmp_path: Path):
        file_path = tmp_path / "events.json"
        json_str = manager_with_history.export_events_json(filepath=file_path)

        assert file_path.exists()
        loaded = json.loads(json_str)
        assert len(loaded) == 3
        assert loaded[0]["tag"] == "PRESS_HI"
        assert loaded[0]["state_transition"] == "NORMAL -> UNACKNOWLEDGED"
        assert loaded[1]["state_transition"] == "UNACKNOWLEDGED -> ACKNOWLEDGED"
        assert loaded[2]["tag"] == "TEMP_HI"

    def test_export_state_json(self, manager_with_history: AlarmManager, tmp_path: Path):
        file_path = tmp_path / "state.json"
        json_str = manager_with_history.export_state_json(filepath=file_path)

        assert file_path.exists()
        loaded = json.loads(json_str)
        assert "PRESS_HI" in loaded
        assert "TEMP_HI" in loaded
        assert loaded["PRESS_HI"]["state"] == "ACKNOWLEDGED"
        assert loaded["TEMP_HI"]["state"] == "UNACKNOWLEDGED"

    def test_export_full_audit_json(self, manager_with_history: AlarmManager, tmp_path: Path):
        file_path = tmp_path / "audit.json"
        json_str = manager_with_history.export_full_audit_json(filepath=file_path)

        loaded = json.loads(json_str)
        assert loaded["standard"] == "ANSI/ISA-18.2-2016"
        assert loaded["summary"]["active_count"] == 2
        assert len(loaded["events"]) == 3
        assert len(loaded["active_alarms"]) == 2

    def test_deterministic_reproducibility(self, manager_with_history: AlarmManager):
        json1 = manager_with_history.export_full_audit_json()
        json2 = manager_with_history.export_full_audit_json()
        assert json1 == json2


class TestValidationAndEdgeCases:
    """Validate boundary checks, schema validation, and error safety."""

    def test_duplicate_tag_rejected(self):
        mgr = AlarmManager()
        defn = AlarmDefinition(tag="ALM_DUP", bound_bit="%M1")
        mgr.register_alarm(defn)
        with pytest.raises(ValueError, match="already registered"):
            mgr.register_alarm(defn)

    def test_empty_tag_or_bound_bit_rejected(self):
        with pytest.raises(ValidationError):
            AlarmDefinition(tag="", bound_bit="%M1")
        with pytest.raises(ValidationError):
            AlarmDefinition(tag="ALM_TEST", bound_bit="")

    def test_negative_deadband_or_delay_rejected(self):
        with pytest.raises(ValidationError):
            AlarmDefinition(tag="ALM_TEST", bound_bit="%M1", deadband=-1.0)
        with pytest.raises(ValidationError):
            AlarmDefinition(tag="ALM_TEST", bound_bit="%M1", delay_ms=-10.0)

    def test_unregister_alarm(self):
        mgr = AlarmManager()
        defn = AlarmDefinition(tag="TEMP_ALM", bound_bit="%M1")
        mgr.register_alarm(defn)
        assert mgr.total_registered == 1
        removed = mgr.unregister_alarm("TEMP_ALM")
        assert removed is not None
        assert removed.tag == "TEMP_ALM"
        assert mgr.total_registered == 0
        assert mgr.get_alarm("TEMP_ALM") is None

    def test_unregistered_tag_raises_key_error(self):
        mgr = AlarmManager()
        with pytest.raises(KeyError):
            mgr.trip("UNKNOWN")
        with pytest.raises(KeyError):
            mgr.acknowledge("UNKNOWN")
        with pytest.raises(KeyError):
            mgr.clear("UNKNOWN")
        with pytest.raises(KeyError):
            mgr.shelve("UNKNOWN")
        with pytest.raises(KeyError):
            mgr.unshelve("UNKNOWN")
        with pytest.raises(KeyError):
            mgr.get_state("UNKNOWN")

    def test_export_summary_json(self, tmp_path: Path):
        mgr = AlarmManager()
        mgr.register_alarm(AlarmDefinition(tag="ALM1", bound_bit="%M1"))
        mgr.trip("ALM1")
        file_path = tmp_path / "summary.json"
        json_str = mgr.export_summary_json(filepath=file_path)
        assert file_path.exists()
        summary = json.loads(json_str)
        assert summary["total_registered"] == 1
        assert summary["active_count"] == 1

    def test_register_alarms_batch(self):
        mgr = AlarmManager()
        defs = [
            AlarmDefinition(tag="A1", bound_bit="%M1"),
            AlarmDefinition(tag="A2", bound_bit="%M2"),
        ]
        registered = mgr.register_alarms(defs)
        assert len(registered) == 2
        assert mgr.total_registered == 2

    def test_get_events_filtering(self):
        mgr = AlarmManager()
        mgr.register_alarm(AlarmDefinition(tag="A1", bound_bit="%M1", severity=AlarmSeverity.LOW))
        mgr.register_alarm(AlarmDefinition(tag="A2", bound_bit="%M2", severity=AlarmSeverity.CRITICAL))

        mgr.trip("A1")
        mgr.trip("A2")
        mgr.clear("A1")

        # By tag
        a1_events = mgr.get_events(tag="A1")
        assert len(a1_events) == 2
        assert all(e.tag == "A1" for e in a1_events)

        # By severity
        crit_events = mgr.get_events(severity=AlarmSeverity.CRITICAL)
        assert len(crit_events) == 1
        assert crit_events[0].tag == "A2"

        # By min_severity
        high_plus = mgr.get_events(min_severity=AlarmSeverity.HIGH)
        assert len(high_plus) == 1
        assert high_plus[0].tag == "A2"

        # By limit
        limited = mgr.get_events(limit=2)
        assert len(limited) == 2

    def test_severity_ordering_and_comparisons(self):
        assert AlarmSeverity.LOW < AlarmSeverity.MEDIUM
        assert AlarmSeverity.MEDIUM <= AlarmSeverity.HIGH
        assert AlarmSeverity.CRITICAL > AlarmSeverity.HIGH
        assert AlarmSeverity.HIGH >= AlarmSeverity.HIGH
        assert AlarmSeverity.CRITICAL.level == 4
        assert AlarmSeverity.LOW.level == 1
        assert AlarmSeverity.LOW < "HIGH"
        with pytest.raises(TypeError):
            _ = AlarmSeverity.LOW < 12345
        with pytest.raises(TypeError):
            _ = AlarmSeverity.LOW < "NON_EXISTENT_SEVERITY"

    def test_custom_clock_injection(self):
        deterministic_time = "2026-10-02T15:30:00.000000Z"
        mgr = AlarmManager(clock_fn=lambda: deterministic_time)
        mgr.register_alarm(AlarmDefinition(tag="A1", bound_bit="%M1"))
        evt = mgr.trip("A1")
        assert evt.timestamp_utc == deterministic_time

    def test_evaluate_scan_alias(self):
        mgr = AlarmManager()
        mgr.register_alarm(AlarmDefinition(tag="A1", bound_bit="%M1"))
        evts = mgr.evaluate_scan(values={"%M1": True})
        assert len(evts) == 1
        assert mgr.get_state("A1") == AlarmState.UNACKNOWLEDGED

    def test_circular_buffer_operations(self):
        with pytest.raises(ValueError):
            CircularEventBuffer(capacity=0)

        buf = CircularEventBuffer(capacity=5)
        for i in range(3):
            buf.append(
                AlarmEvent(
                    event_id=f"EVT-{i}",
                    tag="T",
                    timestamp_utc=format_utc_microsecond(),
                    state_transition="A->B",
                    value=i,
                    message="msg",
                )
            )

        assert len(buf) == 3
        sliced = buf[0:2]
        assert len(sliced) == 2
        assert buf[1].event_id == "EVT-1"

        buf.clear()
        assert len(buf) == 0
        assert buf.total_recorded == 0

    def test_idempotent_and_no_op_state_transitions(self):
        mgr = AlarmManager()
        mgr.register_alarm(AlarmDefinition(tag="A1", bound_bit="%M1"))

        # In NORMAL, clearing or acknowledging does nothing
        assert mgr.clear("A1") is None
        assert mgr.acknowledge("A1") is None
        assert mgr.get_state("A1") == AlarmState.NORMAL

        # Trip to UNACK
        mgr.trip("A1")
        # Tripping again while already abnormal doesn't re-emit transition
        assert mgr.trip("A1") is None
        assert mgr.get_state("A1") == AlarmState.UNACKNOWLEDGED

        # Shelving when already shelved
        mgr.shelve("A1", reason="test")
        assert mgr.shelve("A1") is None

        # Unshelving an un-shelved alarm
        mgr.unshelve("A1")  # goes to UNACK
        assert mgr.unshelve("A1") is None  # no-op

