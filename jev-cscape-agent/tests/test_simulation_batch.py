"""Comprehensive Test Suite for Multi-Scenario Plant Simulation Batch Coordinator.

Work Package: W041 (Gate G4 Pure-Software Simulation & Validation)
Classification: PRODUCTION_READY [Deterministic Multi-Scenario Simulation Engine]

Validates:
1. run_scenario_normal executes cleanly with PI regulation and mass conservation.
2. run_scenario_drought handles restricted inflow and verifies low-level alarms.
3. run_scenario_surge handles Poisson stochastic load steps and recovers cleanly.
4. run_scenario_esd executes failsafe gravity drainage following simulated trip.
5. run_simulation_batch coordinates parallel execution, validates 4-state contract,
   and exports artifacts/simulation/batch_simulation_evidence.json.
6. CLI entrypoint main() executes and returns 0 exit code.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from scripts.run_simulation_batch import (
    ScenarioResult,
    main,
    run_scenario_drought,
    run_scenario_esd,
    run_scenario_normal,
    run_scenario_surge,
    run_simulation_batch,
)


def test_scenario_normal_execution() -> None:
    """Verify normal continuous regulation scenario passes deterministically."""
    res = run_scenario_normal(cycles=2000, dt_ms=10.0, seed=42)
    assert isinstance(res, ScenarioResult)
    assert res.status == "success"
    assert res.scenario_id == "SCENARIO_01_NORMAL"
    assert res.cycles == 2000
    assert res.mass_balance_error < 1e-6
    assert res.final_level1_pct >= 0.0
    assert res.final_level2_pct >= 0.0


def test_scenario_drought_execution() -> None:
    """Verify drought scenario handles inflow restriction and low level alarms."""
    res = run_scenario_drought(cycles=800, dt_ms=10.0, seed=43)
    assert isinstance(res, ScenarioResult)
    assert res.status == "success"
    assert res.scenario_id == "SCENARIO_02_DROUGHT"
    assert res.cycles == 800
    assert res.mass_balance_error < 1e-6
    assert "T1_LOW" in res.alarms_triggered or "T2_LOW" in res.alarms_triggered


def test_scenario_surge_execution() -> None:
    """Verify storm surge scenario recovers from stochastic load disturbances."""
    res = run_scenario_surge(cycles=1000, dt_ms=10.0, seed=44)
    assert isinstance(res, ScenarioResult)
    assert res.status == "success"
    assert res.scenario_id == "SCENARIO_03_SURGE"
    assert res.cycles == 1000
    assert res.mass_balance_error < 1e-6
    assert res.final_level1_pct >= 0.0


def test_scenario_esd_execution() -> None:
    """Verify emergency shutdown scenario drains tanks safely via Torricelli."""
    res = run_scenario_esd(cycles=800, dt_ms=10.0, seed=45)
    assert isinstance(res, ScenarioResult)
    assert res.status == "success"
    assert res.scenario_id == "SCENARIO_04_ESD"
    assert res.cycles == 800
    assert res.mass_balance_error < 1e-6
    assert res.final_level1_pct < 65.0
    assert res.final_level2_pct < 55.0
    assert "ESD_TRIP_ACTIVE" in res.alarms_triggered


def test_run_simulation_batch_full_contract(tmp_path: Path) -> None:
    """Verify multi-scenario batch coordinator executes parallel workers and returns 4-state contract."""
    evidence_file = tmp_path / "batch_simulation_evidence.json"

    result = run_simulation_batch(
        output_path=str(evidence_file),
        max_workers=2,
        dt_ms=10.0,
        seed_base=200,
    )

    # 1. Strict 4-state envelope
    assert isinstance(result, dict)
    assert result["status"] == "success"
    assert result["error_code"] is None
    assert isinstance(result["details"], str)
    assert "Simulation batch coordinator completed" in result["details"]

    data = result["data"]
    assert data["gate"] == "G4"
    assert data["work_package"] == "W041"
    assert data["verdict"] == "success"
    assert data["total_cycles_executed"] > 0
    assert data["scenarios_passed"] == 4
    assert data["scenarios_failed"] == 0
    assert len(data["scenarios"]) == 4

    # 2. Invariants
    inv = data["invariants"]
    assert inv["pure_software_execution"] is True
    assert inv["offline_mock_mode"] is True
    assert inv["zero_hardware_leakage"] is True
    assert inv["mass_conservation_verified"] is True
    assert inv["zero_nan_verified"] is True

    # 3. Artifact on disk
    assert evidence_file.exists()
    with open(evidence_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["status"] == "success"
    assert len(loaded["data"]["scenarios"]) == 4


def test_simulation_batch_cli_entrypoint(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify CLI main entrypoint executes cleanly and returns exit code 0."""
    out_file = tmp_path / "cli_batch_out.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "run_simulation_batch.py",
            "--output",
            str(out_file),
            "--workers",
            "2",
            "--dt-ms",
            "10.0",
        ],
    )
    exit_code = main()
    assert exit_code == 0
    assert out_file.exists()
