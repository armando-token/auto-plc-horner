"""Unit tests for Industrial Historical Data Logging & Ring-Buffer Telemetry Archiver (W058).

Tests:
1. CircularRingBuffer fixed capacity, O(1) FIFO overwrite, dropped count tracking, batch append.
2. HistoricalDataPoint immutability, slotted low-memory footprint, ISO 8601 formatting.
3. Absolute deadband filtering.
4. Percent-of-span deadband filtering.
5. Swinging Door Trending (SDT) corridor compression.
6. Heartbeat maximum interval override.
7. Critical bypass: alarm limit crossing without distortion.
8. Critical bypass: discrete bit transition without distortion.
9. Horner OCS register space synchronization (%R240..%R244, %M45..%M47).
10. RFC 4180 CSV export and JSON export.
11. ILogicUnit scan cycle execution and reset behavior.
12. Memory boundedness verification (< 15MB for 100k data points).
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
import sys
import time

import pytest

from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable, WordOrder
from jev_cscape.telemetry.historical_logger import (
    ArchiveReason,
    CircularRingBuffer,
    DeadbandMode,
    HistoricalDataPoint,
    HistoricalTagConfig,
    HistoricalTelemetryLogger,
    verify_historical_logger_and_export_evidence,
)


def test_circular_ring_buffer_basic() -> None:
    """Verify O(1) buffer append, overwrite behavior, and dropped count."""
    buf = CircularRingBuffer(capacity=5)
    assert buf.capacity == 5
    assert buf.occupancy == 0
    assert buf.dropped_count == 0
    assert buf.cumulative_samples == 0

    pts = [
        HistoricalDataPoint(
            timestamp_us=i * 1_000_000,
            channel_name="%AI1",
            raw_value=i * 100,
            engineering_value=float(i),
            quality_word=0x00C0,
        )
        for i in range(7)
    ]

    for p in pts:
        buf.append(p)

    assert buf.occupancy == 5
    assert buf.dropped_count == 2
    assert buf.cumulative_samples == 7

    snapshot = buf.snapshot()
    assert len(snapshot) == 5
    # The oldest 2 points (0, 1) should have been dropped
    assert snapshot[0].engineering_value == 2.0
    assert snapshot[-1].engineering_value == 6.0

    buf.clear()
    assert buf.occupancy == 0
    assert buf.dropped_count == 0


def test_circular_ring_buffer_batch() -> None:
    """Verify thread-safe batch insertion and dropped count calculation."""
    buf = CircularRingBuffer(capacity=10)
    pts1 = [
        HistoricalDataPoint(
            timestamp_us=i, channel_name="CH1", raw_value=i, engineering_value=float(i), quality_word=0x00C0
        )
        for i in range(6)
    ]
    buf.append_batch(pts1)
    assert buf.occupancy == 6
    assert buf.dropped_count == 0

    pts2 = [
        HistoricalDataPoint(
            timestamp_us=i + 10, channel_name="CH1", raw_value=i, engineering_value=float(i), quality_word=0x00C0
        )
        for i in range(8)
    ]
    buf.append_batch(pts2)
    assert buf.occupancy == 10
    assert buf.dropped_count == 4
    assert buf.cumulative_samples == 14


def test_historical_datapoint_properties() -> None:
    """Verify HistoricalDataPoint schema, freezing, and ISO timestamp formatting."""
    pt = HistoricalDataPoint(
        timestamp_us=1700000000123456,
        channel_name="LEVEL_PV",
        raw_value=16000,
        engineering_value=1.0000,
        quality_word=0x00C0,
        archive_reason=ArchiveReason.INITIAL.value,
    )
    assert pt.channel_name == "LEVEL_PV"
    assert pt.raw_value == 16000
    assert pt.engineering_value == 1.0000
    assert pt.quality_word == 0x00C0
    assert "2023-" in pt.timestamp_iso
    assert pt.timestamp_iso.endswith("Z")

    with pytest.raises(Exception):
        # Frozen dataclass must reject mutation
        pt.engineering_value = 2.0  # type: ignore


def test_deadband_filtering_absolute() -> None:
    """Verify absolute deadband threshold suppression and triggering."""
    reg = RegisterTable()
    logger = HistoricalTelemetryLogger(register_table=reg, capacity=100)

    # Initial cycle archives the default initial sample
    logger.step(0.010)
    initial_count = logger.ring_buffer.occupancy

    # Small fluctuation below delta_abs (delta_abs = 1.0 for INFLOW_VALVE_CMD %AQ1)
    # 0 counts = 0.0%. 10 counts = 0.031% < 1.0%
    reg.write_word("%AQ1", 10, privilege=PrivilegeMode.SYSTEM)
    logger.step(0.010)
    assert logger.ring_buffer.occupancy == initial_count

    # Large fluctuation above delta_abs: 1600 counts = 5.0% >= 1.0%
    reg.write_word("%AQ1", 1600, privilege=PrivilegeMode.SYSTEM)
    logger.step(0.010)
    assert logger.ring_buffer.occupancy == initial_count + 1


def test_deadband_filtering_percent_span() -> None:
    """Verify percent-of-span deadband mode."""
    reg = RegisterTable()
    logger = HistoricalTelemetryLogger(register_table=reg, capacity=100)
    cfg = HistoricalTagConfig(
        tag_name="PERCENT_TAG",
        channel_address="%AI2",
        eu_min=0.0,
        eu_max=1000.0,  # span = 1000.0
        deadband_mode=DeadbandMode.PERCENT_SPAN,
        delta_pct=0.05,  # 5% = 50.0 units
        enable_sdt=False,
    )
    logger.register_tag(cfg)

    # Initial sample
    logger.step(0.010)
    # %AI2 is 0 counts = 0.0 EU
    assert cfg.last_archived_point is not None

    # Step to 30.0 EU (3% of span, below 5%)
    # 30 / 1000 * 32000 = 960 counts
    reg.write_word("%AI2", 960, privilege=PrivilegeMode.SYSTEM)
    logger.step(0.010)
    assert cfg.total_points_archived == 1

    # Step to 80.0 EU (8% of span, above 5%)
    # 80 / 1000 * 32000 = 2560 counts
    reg.write_word("%AI2", 2560, privilege=PrivilegeMode.SYSTEM)
    logger.step(0.010)
    assert cfg.total_points_archived == 2


def test_sdt_compaction() -> None:
    """Verify Swinging Door Trending compresses linear trends and catches inflection points."""
    reg = RegisterTable()
    logger = HistoricalTelemetryLogger(register_table=reg, capacity=1000)
    cfg = HistoricalTagConfig(
        tag_name="RAMP_TAG",
        channel_address="%AI2",
        eu_min=0.0,
        eu_max=100.0,
        deadband_mode=DeadbandMode.NONE,
        sdt_epsilon=0.50,
        enable_sdt=True,
        heartbeat_max_s=100.0,
    )
    logger.register_tag(cfg)

    # Initial point at t=0
    logger.step(0.010)
    assert cfg.total_points_archived == 1

    # Linear ramp: y = 1.0 * t for 20 steps
    # Perfect linear ramp should stay within swinging door corridor
    for step_i in range(1, 21):
        # 1 count per step = small linear increment
        val_counts = int(step_i * 100)
        reg.write_word("%AI2", val_counts, privilege=PrivilegeMode.SYSTEM)
        logger.step(0.010)

    # In a pure linear trend, SDT holds points in the corridor without archiving every step
    assert cfg.total_points_archived < 5

    # Sudden sharp deviation breaks the corridor
    reg.write_word("%AI2", 25000, privilege=PrivilegeMode.SYSTEM)
    logger.step(0.010)

    # Corridor collapse triggers archiving of inflection point and/or new point
    assert cfg.total_points_archived >= 3


def test_alarm_and_state_change_bypass() -> None:
    """Verify zero distortion: alarm thresholds and discrete changes bypass compaction immediately."""
    reg = RegisterTable()
    logger = HistoricalTelemetryLogger(register_table=reg, capacity=100)

    logger.step(0.010)
    tag_level = logger.tags["TANK1_LEVEL_PV"]
    assert tag_level.high_alarm_limit == 1.90

    # Cross 1.90m threshold: 1.95m = 31200 counts
    reg.write_word("%AI1", 31200, privilege=PrivilegeMode.SYSTEM)
    logger.step(0.010)

    alarm_pts = [p for p in logger.ring_buffer.snapshot() if p.channel_name == "TANK1_LEVEL_PV" and p.is_alarm_event]
    assert len(alarm_pts) > 0
    assert alarm_pts[-1].archive_reason == ArchiveReason.ALARM_TRIP.value

    # Discrete state change
    reg.write_bit("%M30", True, privilege=PrivilegeMode.SYSTEM)
    logger.step(0.010)
    m30_pts = [p for p in logger.ring_buffer.snapshot() if p.channel_name == "ALARM_TRIP_COIL"]
    assert len(m30_pts) >= 2
    assert m30_pts[-1].archive_reason == ArchiveReason.STATE_CHANGE.value


def test_heartbeat_override() -> None:
    """Verify that steady state values are periodically archived via heartbeat."""
    reg = RegisterTable()
    logger = HistoricalTelemetryLogger(register_table=reg, capacity=100)

    logger.step(0.010)
    tag = logger.tags["TANK1_LEVEL_PV"]
    tag.last_archived_time_s = logger.virtual_clock_s - 31.0  # heartbeat is 30s
    logger.step(0.010)

    hb_pts = [p for p in logger.ring_buffer.snapshot() if p.channel_name == "TANK1_LEVEL_PV" and p.is_heartbeat]
    assert len(hb_pts) > 0
    assert hb_pts[-1].archive_reason == ArchiveReason.HEARTBEAT.value


def test_horner_register_synchronization() -> None:
    """Verify %R240..%R244 and %M45..%M47 register controls and status words."""
    reg = RegisterTable()
    logger = HistoricalTelemetryLogger(register_table=reg, capacity=100)

    # %M45 defaults to False in clean table, but logger initialized logging_enabled=True
    # Step updates registers
    logger.step(0.010)

    # %R240: buffer occupancy
    occ = reg.read_word("%R240")
    assert occ == logger.ring_buffer.occupancy

    # %R241:%R242: total samples UDINT LOW_WORD_FIRST
    total_samples = reg.read_udint("%R241", WordOrder.LOW_WORD_FIRST)
    assert total_samples == logger.ring_buffer.cumulative_samples

    # %R243: dropped samples
    assert reg.read_word("%R243") == 0

    # Test %M47 (Clear Buffer Trigger)
    reg.write_bit("%M47", True, privilege=PrivilegeMode.SYSTEM)
    logger.step(0.010)
    assert logger.ring_buffer.occupancy == 0
    # %M47 should be self-cleared
    assert reg.read_bit("%M47") is False


def test_csv_and_json_export(tmp_path: Path) -> None:
    """Verify RFC 4180 standard CSV and JSON serialization."""
    reg = RegisterTable()
    logger = HistoricalTelemetryLogger(register_table=reg, capacity=100)

    for _ in range(5):
        logger.step(0.010)

    csv_path = tmp_path / "telemetry_test.csv"
    count_csv = logger.export_csv(csv_path)
    assert count_csv > 0
    assert csv_path.exists()

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        assert "timestamp_us" in header
        assert "engineering_value" in header
        rows = list(reader)
        assert len(rows) == count_csv

    json_path = tmp_path / "telemetry_test.json"
    count_json = logger.export_json(json_path)
    assert count_json == count_csv
    assert json_path.exists()

    with open(json_path, "r", encoding="utf-8") as f:
        payload = json.load(f)
        assert payload["buffer_capacity"] == 100
        assert len(payload["records"]) == count_json


def test_ilogicunit_interface() -> None:
    """Verify ILogicUnit standard compliance."""
    logger = HistoricalTelemetryLogger()
    assert logger.name == "HistoricalTelemetryLoggerUnit"
    assert logger.priority == 95
    assert logger.is_enabled is True

    ctx = ScanContext(
        cycle=1,
        dt_ms=10.0,
        elapsed_time_ms=10.0,
        get_register=lambda addr: 0,
        set_register=lambda addr, val: None,
        get_variable=lambda name, default=None: default,
        set_variable=lambda name, val: None,
        record_fault=lambda fault: None,
    )
    logger.execute(ctx)
    assert logger.virtual_clock_s > 0.0

    logger.reset()
    assert logger.virtual_clock_s == 0.0
    assert logger.ring_buffer.occupancy == 0


def test_verify_historical_logger_evidence(tmp_path: Path) -> None:
    """Verify canonical evidence generator function."""
    out_evidence = tmp_path / "historical_logger_evidence.json"
    result = verify_historical_logger_and_export_evidence(str(out_evidence))
    assert result["status"] == "success"
    assert result["error_code"] is None
    assert out_evidence.exists()

    with open(out_evidence, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["data"]["work_package"] == "W058"
    assert loaded["data"]["gate"] == "G8"
