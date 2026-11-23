"""Tests for Sensor Calibration Matrix & Dual-Channel Signal Conditioner (Gate G8, W044)."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.simulation.register_table import RegisterTable
from jev_cscape.telemetry.calibration import (
    CalibrationCurve,
    CalibrationPoint,
    ConditionedSignal,
    RedundancyMode,
    RedundantSensorConditioner,
    SensorCalibrationMatrix,
    SensorFaultState,
)
from jev_cscape.telemetry.scaling_bridge import (
    OPCQualityFlag,
    QualityCode,
)
from scripts.run_calibration_verification import run_calibration_verification


def test_linear_calibration_curve() -> None:
    """Verify linear zero-offset and span factor adjustments."""
    curve = CalibrationCurve(
        curve_id="CAL_TEST",
        channel_name="%AI1",
        zero_offset=1.5,
        span_factor=1.02,
    )
    # raw = 100.0 -> (100.0 - 1.5) * 1.02 = 98.5 * 1.02 = 100.47
    result = curve.apply(100.0)
    assert abs(result - 100.47) < 1e-6


def test_thermal_drift_compensation() -> None:
    """Verify temperature drift compensation applies thermal multiplier correctly."""
    curve = CalibrationCurve(
        curve_id="CAL_TEMP",
        channel_name="%AI1",
        zero_offset=0.0,
        span_factor=1.0,
        temp_coefficient=0.001,  # 0.1%/°C
        reference_temp_c=25.0,
    )
    # At ref temp (25°C): multiplier = 1.0
    assert abs(curve.apply(50.0, ambient_temp_c=25.0) - 50.0) < 1e-6

    # At elevated temp (45°C): delta_t = +20°C -> multiplier = 1.0 + 0.001*20 = 1.02 -> 51.0
    val_hot = curve.apply(50.0, ambient_temp_c=45.0)
    assert abs(val_hot - 51.0) < 1e-6


def test_piecewise_interpolation() -> None:
    """Verify multi-point non-linear calibration piecewise interpolation."""
    pts = [
        CalibrationPoint(raw_counts=0.0, engineering_units=0.0),
        CalibrationPoint(raw_counts=50.0, engineering_units=45.0),
        CalibrationPoint(raw_counts=100.0, engineering_units=100.0),
    ]
    curve = CalibrationCurve(
        curve_id="CAL_PW",
        channel_name="%AI1",
        piecewise_points=pts,
    )
    # At raw=25.0 (midway between 0 and 50): EU = 22.5
    assert abs(curve.apply(25.0) - 22.5) < 1e-6
    # Below min: clamp to 0.0
    assert curve.apply(-10.0) == 0.0
    # Above max: clamp to 100.0
    assert curve.apply(120.0) == 100.0


def test_redundant_sensor_conditioner_average_mode() -> None:
    """Verify dual-channel averaging when both sensors are healthy and in agreement."""
    regs = RegisterTable()
    cond = RedundantSensorConditioner(
        signal_name="Test_Average",
        primary_channel="%AI1",
        secondary_channel="%AI2",
        mode=RedundancyMode.AVERAGE,
        divergence_threshold_eu=2.0,
        discrepancy_alarm_register="%M1",
    )
    sig = cond.condition_signals(
        raw_pri_val=50.0,
        raw_sec_val=51.0,
        register_table=regs,
    )
    assert sig.quality_code == QualityCode.GOOD
    assert not sig.is_divergent
    assert abs(sig.reconciled_value - 50.5) < 1e-4
    assert sig.active_channel == "AVERAGE"
    assert regs.read_register("%M1") is False


def test_redundant_sensor_conditioner_divergence_alarm() -> None:
    """Verify divergence exceeds threshold sets UNCERTAIN quality and alarm register."""
    regs = RegisterTable()
    cond = RedundantSensorConditioner(
        signal_name="Test_Divergence",
        primary_channel="%AI1",
        secondary_channel="%AI2",
        mode=RedundancyMode.AVERAGE,
        divergence_threshold_eu=2.0,
        discrepancy_alarm_register="%M1",
    )
    sig = cond.condition_signals(
        raw_pri_val=50.0,
        raw_sec_val=55.0,  # Delta = 5.0 > 2.0 threshold
        register_table=regs,
    )
    assert sig.is_divergent is True
    assert sig.quality_code == QualityCode.UNCERTAIN
    assert "SENSOR_DIVERGENCE_LIMIT_EXCEEDED" in sig.fault_flags
    assert regs.read_register("%M1") is True


def test_automatic_burnout_failover() -> None:
    """Verify automatic failover to secondary backup transmitter when primary fails."""
    regs = RegisterTable()
    cond = RedundantSensorConditioner(
        signal_name="Test_Failover",
        primary_channel="%AI1",
        secondary_channel="%AI2",
        mode=RedundancyMode.AVERAGE,
    )
    sig = cond.condition_signals(
        raw_pri_val=0.0,
        raw_sec_val=50.0,
        pri_ne43_state=SensorFaultState.BURNOUT,  # Primary burned out (<3.6mA)
        sec_ne43_state=SensorFaultState.NORMAL,
        register_table=regs,
    )
    assert sig.active_channel == "SECONDARY_BACKUP"
    assert abs(sig.reconciled_value - 50.0) < 1e-4
    assert "AUTO_FAILOVER_TO_SECONDARY" in sig.fault_flags
    assert cond.failover_count == 1


def test_dual_sensor_total_failure() -> None:
    """Verify total sensor failure reports BAD quality and zero output."""
    regs = RegisterTable()
    cond = RedundantSensorConditioner(
        signal_name="Test_TotalFailure",
        primary_channel="%AI1",
        secondary_channel="%AI2",
    )
    sig = cond.condition_signals(
        raw_pri_val=0.0,
        raw_sec_val=0.0,
        pri_ne43_state=SensorFaultState.BURNOUT,
        sec_ne43_state=SensorFaultState.SHORT_CIRCUIT,
        register_table=regs,
    )
    assert sig.quality_code == QualityCode.BAD
    assert sig.active_channel == "NONE_AVAILABLE"
    assert "DUAL_TRANSMITTER_TOTAL_FAILURE" in sig.fault_flags


def test_sensor_calibration_matrix_export(tmp_path: Path) -> None:
    """Verify matrix export produces valid JSON artifact."""
    matrix = SensorCalibrationMatrix()
    out_file = tmp_path / "cal_evidence.json"
    evidence = matrix.export_evidence_artifact(output_file=out_file)

    assert out_file.exists()
    assert evidence["status"] == "success"
    assert "nominal_condition" in evidence["verification_scenarios"]
    assert "primary_burnout_failover" in evidence["verification_scenarios"]


def test_run_calibration_verification_script(tmp_path: Path) -> None:
    """Verify canonical script runner executes without errors."""
    res = run_calibration_verification(repo_root=tmp_path)
    assert res.status == AgentStatus.SUCCESS
    assert res.data["total_conditioners"] >= 2
    assert Path(res.data["evidence_path"]).exists()
