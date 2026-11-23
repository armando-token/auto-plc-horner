"""Unit and Integration Test Suite for Plant Process Anomaly Supervisor.

Work Package: W047 (Gate G7 Plant Dynamics & Gate G4 Pure-Software Simulation)
Classification: PRODUCTION_READY
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.simulation.anomaly import (
    AnomalySupervisorConfig,
    ProcessAnomalySupervisor,
)
from jev_cscape.simulation.register_table import RegisterTable
from scripts.run_anomaly_supervisor_verification import (
    run_anomaly_supervisor_verification,
)


def test_anomaly_supervisor_nominal() -> None:
    """Verify nominal plant operation triggers zero anomaly alarms."""
    regs = RegisterTable()
    regs.set_register("%AQ1", 5000)
    regs.set_register("%Q1", True)

    sup = ProcessAnomalySupervisor(register_table=regs)
    sup._estimated_level_pv = 50.0
    for cycle in range(1, 100):
        level = sup._estimated_level_pv + ((cycle % 5) - 2) * 0.05
        regs.set_input("%AI1", int(level * 100))
        regs.set_input("%AI3", int(level * 100))
        sup.execute_scan(cycle, dt_ms=10.0)

    assert sup.pipe_clog_active is False
    assert sup.cavitation_active is False
    assert sup.sensor_freeze_active is False
    assert regs.read_register("%M17") is False
    assert regs.read_register("%M18") is False
    assert regs.read_register("%M20") is False


def test_pipe_clogging_detection_and_emergency_drain() -> None:
    """Verify pipe clogging triggers emergency drain %Q3 and clamps inlet %AQ1."""
    regs = RegisterTable()
    regs.set_input("%AI1", 4000)
    regs.set_register("%AQ1", 7000)
    regs.set_register("%Q1", True)

    sup = ProcessAnomalySupervisor(register_table=regs)
    for cycle in range(1, 150):
        level = 40.0 + min(45.0, cycle * 0.4)
        regs.set_input("%AI1", int(level * 100))
        sup.execute_scan(cycle, dt_ms=10.0)

    assert sup.pipe_clog_active is True
    assert regs.read_register("%M17") is True
    assert regs.read_register("%Q3") is True
    assert regs.read_register("%AQ1") <= 1500


def test_pump_cavitation_detection_and_trip() -> None:
    """Verify low suction head (< 10%) trips pump %Q1 and zeroes speed %AQ2."""
    regs = RegisterTable()
    regs.set_input("%AI1", 600)  # 6.0% level
    regs.set_register("%Q1", True)
    regs.set_register("%AQ2", 7500)

    sup = ProcessAnomalySupervisor(register_table=regs)
    sup.execute_scan(1, dt_ms=10.0)

    assert sup.cavitation_active is True
    assert regs.read_register("%M18") is True
    assert regs.read_register("%Q1") is False
    assert regs.read_register("%AQ2") == 0


def test_sensor_freeze_detection_and_failover() -> None:
    """Verify stagnant sensor reading triggers failover to backup sensor %AI3."""
    regs = RegisterTable()
    regs.set_input("%AI1", 5000)  # Frozen
    regs.set_input("%AI3", 7200)  # True backup level
    regs.set_register("%AQ1", 8000)

    sup = ProcessAnomalySupervisor(register_table=regs)
    for cycle in range(1, 100):
        sup.execute_scan(cycle, dt_ms=10.0)

    assert sup.sensor_freeze_active is True
    assert regs.read_register("%M20") is True
    assert regs.read_register("%AI1") == 7200


def test_run_anomaly_supervisor_verification_runner(tmp_path: Path) -> None:
    """Verify canonical script runner executes without errors in tmp directory."""
    out_file = tmp_path / "anomaly_evidence.json"
    res = run_anomaly_supervisor_verification(output_path=str(out_file))

    assert res.status == AgentStatus.SUCCESS
    assert out_file.is_file()
    with open(out_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["status"] == "success"
    assert "scenario_01_nominal" in loaded["scenarios_verified"]
    assert "scenario_02_pipe_clogging" in loaded["scenarios_verified"]
    assert "scenario_03_pump_cavitation" in loaded["scenarios_verified"]
    assert "scenario_04_sensor_freeze" in loaded["scenarios_verified"]
