"""Deterministic Closed-Loop Simulation Test Matrix and Verification Runner Suite.

Work Package: W022 (Gate G4)
Classification: TESTED_MOCK [offline/DEV only]

Validates:
1. IEC 61131-3 PI level controller dynamics, anti-windup clamping, and reset.
2. Safety interlocks: High-High valve trip, Low-Low pump trip, and Emergency Stop (ESD).
3. Scenario 1: Setpoint tracking & regulation across multiple steps (error <= 1.5%).
4. Scenario 2: Outflow demand disturbance surge injection and recovery.
5. Scenario 3: Schmitt-trigger alarm hysteresis deadband retention and reset.
6. Scenario 4: Single-cycle emergency shutdown (ESD) de-energization.
7. Scenario 5: Multi-rate stability across 5ms, 10ms, 20ms, 50ms scan rates with noise.
8. Evidence artifact export: schema conformance, metrics completeness, invariant audit.
9. Anti-Straton and hardware safety invariants (zero COM ports, zero downloads).
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.simulation.engine import SimulationEngine
from jev_cscape.simulation.plant_model import (
    PlantModelLogicUnit,
    TankConfig,
    TankLevelPlantModel,
)
from jev_cscape.simulation.verifier import (
    ClosedLoopPIController,
    ClosedLoopVerifier,
    ScenarioResult,
    ScenarioStatus,
)


# ============================================================================
# 1. PI Controller Initialization & Dynamics
# ============================================================================


def test_pi_controller_initialization() -> None:
    """Verify PI controller default parameters and channel mappings."""
    ctrl = ClosedLoopPIController(
        setpoint_pct=55.0,
        kp=2.5,
        ki=0.8,
        ai_channel="%AI1",
        aq_channel="%AQ1",
        q_pump_channel="%Q1",
    )
    assert ctrl.setpoint_pct == 55.0
    assert ctrl.kp == 2.5
    assert ctrl.ki == 0.8
    assert ctrl.name == "PI_Level_Controller"
    assert ctrl.priority == 100
    assert ctrl.is_enabled is True
    assert ctrl.integral_sum == 0.0
    assert ctrl.last_pv_pct == 0.0
    assert ctrl.last_cv_pct == 0.0
    assert ctrl.esd_active is False


def test_pi_controller_reset() -> None:
    """Verify controller reset clears internal integrator and states."""
    ctrl = ClosedLoopPIController()
    ctrl.integral_sum = 15.0
    ctrl.last_pv_pct = 48.0
    ctrl.last_cv_pct = 60.0
    ctrl.esd_active = True

    ctrl.reset()
    assert ctrl.integral_sum == 0.0
    assert ctrl.last_pv_pct == 0.0
    assert ctrl.last_cv_pct == 0.0
    assert ctrl.esd_active is False


def test_pi_controller_anti_windup_clamping() -> None:
    """Verify integrator does not wind up when actuator command is saturated."""
    engine = SimulationEngine(default_dt_ms=10.0)
    ctrl = ClosedLoopPIController(setpoint_pct=90.0, kp=10.0, ki=5.0)
    engine.attach_logic_unit(ctrl)

    # Set AI1 to 0 (error = 90%) -> large positive saturation
    engine.set_input("%AI1", 0)
    for _ in range(50):
        engine.step()

    # Integrator must not integrate without bound while saturated
    assert ctrl.last_cv_pct == 100.0
    assert ctrl.integral_sum <= 100.0


# ============================================================================
# 2. Safety Interlocks & Trips
# ============================================================================


def test_high_high_alarm_trips_inlet_valve_closed() -> None:
    """Verify High-High alarm (%M3) instantly clamps %AQ1 to 0 and turns pump on."""
    engine = SimulationEngine(default_dt_ms=10.0)
    ctrl = ClosedLoopPIController(setpoint_pct=80.0)
    engine.attach_logic_unit(ctrl)

    # Step normally with level at 50%
    engine.set_input("%AI1", 16000)
    engine.step()
    assert engine.read_word("%AQ1") > 0

    # Trip High-High alarm (%M3)
    engine.write_bit("%M3", True)
    engine.step()

    assert engine.read_word("%AQ1") == 0
    assert engine.read_bit("%Q1") is True
    assert ctrl.last_cv_pct == 0.0


def test_low_low_alarm_stops_pump() -> None:
    """Verify Low-Low alarm (%M4) shuts off pump (%Q1) to prevent dry-running."""
    engine = SimulationEngine(default_dt_ms=10.0)
    ctrl = ClosedLoopPIController(setpoint_pct=50.0)
    engine.attach_logic_unit(ctrl)

    # Trip Low-Low alarm (%M4)
    engine.write_bit("%M4", True)
    engine.set_input("%AI1", 2000)  # low level
    engine.step()

    assert engine.read_bit("%Q1") is False


def test_emergency_shutdown_single_scan_deenergize() -> None:
    """Verify ESD shuts down %AQ1 and %Q1 within exactly 1 scan cycle."""
    engine = SimulationEngine(default_dt_ms=10.0)
    ctrl = ClosedLoopPIController(setpoint_pct=50.0)
    engine.attach_logic_unit(ctrl)

    engine.set_input("%AI1", 10000)
    engine.step()
    assert engine.read_word("%AQ1") > 0

    # Trigger ESD
    ctrl.esd_active = True
    engine.step()

    assert engine.read_word("%AQ1") == 0
    assert engine.read_bit("%Q1") is False


# ============================================================================
# 3. Canonical Closed-Loop Verification Scenarios
# ============================================================================


def test_scenario_1_setpoint_tracking() -> None:
    """Verify Scenario 1: Step responses at 50% and 70% settle with error <= 1.5%."""
    verifier = ClosedLoopVerifier(default_dt_ms=10.0)
    result = verifier.scenario_setpoint_tracking()

    assert result.name == "setpoint_tracking"
    assert result.status == ScenarioStatus.PASSED
    assert result.cycles_executed == 3000
    assert result.duration_ms == 30000.0

    metrics = result.metrics
    assert metrics["target_sp_1"] == 50.0
    assert metrics["error_1"] <= 1.5
    assert metrics["target_sp_2"] == 70.0
    assert metrics["error_2"] <= 1.5


def test_scenario_2_disturbance_rejection() -> None:
    """Verify Scenario 2: Outflow demand surge is detected, dips, and recovers."""
    verifier = ClosedLoopVerifier(default_dt_ms=10.0)
    result = verifier.scenario_disturbance_rejection()

    assert result.name == "disturbance_rejection"
    assert result.status == ScenarioStatus.PASSED
    assert result.cycles_executed == 900

    metrics = result.metrics
    assert metrics["min_pv_during_surge"] < metrics["baseline_pv"]
    assert metrics["recovery_error"] <= 2.0


def test_scenario_3_alarm_hysteresis() -> None:
    """Verify Scenario 3: High-High trip clamps valve, retains trip in deadband, resets below."""
    verifier = ClosedLoopVerifier(default_dt_ms=10.0)
    result = verifier.scenario_alarm_hysteresis()

    assert result.name == "alarm_hysteresis"
    assert result.status == ScenarioStatus.PASSED

    metrics = result.metrics
    assert metrics["hh_tripped"] is True
    assert metrics["valve_clamped_zero"] is True
    assert metrics["tripped_in_deadband"] is True
    assert metrics["cleared_below_deadband"] is True


def test_scenario_4_emergency_shutdown() -> None:
    """Verify Scenario 4: ESD executes single-cycle fail-safe de-energization."""
    verifier = ClosedLoopVerifier(default_dt_ms=10.0)
    result = verifier.scenario_emergency_shutdown()

    assert result.name == "emergency_shutdown"
    assert result.status == ScenarioStatus.PASSED
    assert result.cycles_executed == 51

    metrics = result.metrics
    assert metrics["valve_counts_before_esd"] > 0
    assert metrics["valve_counts_after_esd"] == 0
    assert metrics["pump_running_after_esd"] is False
    assert metrics["response_scans"] == 1


def test_scenario_5_multirate_stability() -> None:
    """Verify Scenario 5: Convergence across 5ms, 10ms, 20ms, 50ms scan rates with noise."""
    verifier = ClosedLoopVerifier()
    result = verifier.scenario_multirate_stability()

    assert result.name == "multirate_stability"
    assert result.status == ScenarioStatus.PASSED

    metrics = result.metrics
    for dt_key in ["5ms", "10ms", "20ms", "50ms"]:
        assert dt_key in metrics
        assert metrics[dt_key]["stable"] is True
        assert metrics[dt_key]["error"] <= 2.0


# ============================================================================
# 4. End-to-End Runner & Evidence Artifact Export
# ============================================================================


def test_verifier_run_all_scenarios() -> None:
    """Verify run_all_scenarios returns all 5 scenarios with PASSED status."""
    verifier = ClosedLoopVerifier()
    results = verifier.run_all_scenarios()

    assert len(results) == 5
    expected_scenarios = {
        "setpoint_tracking",
        "disturbance_rejection",
        "alarm_hysteresis",
        "emergency_shutdown",
        "multirate_stability",
    }
    assert set(results.keys()) == expected_scenarios

    for name, res in results.items():
        assert res.status == ScenarioStatus.PASSED, f"Scenario '{name}' failed: {res.metrics}"


def test_export_evidence_artifact(tmp_path: Path) -> None:
    """Verify export_evidence_artifact generates conforming JSON with all G4 criteria."""
    artifact_file = tmp_path / "closed_loop_simulation_evidence.json"
    verifier = ClosedLoopVerifier()
    artifact = verifier.export_evidence_artifact(output_path=str(artifact_file))

    assert artifact_file.exists()
    assert artifact["gate"] == "G4"
    assert artifact["work_package"] == "W022"
    assert artifact["status"] == "success"
    assert artifact["mode"] == "offline/mock"
    assert artifact["hardware_lockout"] == "FAIL_CLOSED_ACTIVE"
    assert artifact["straton_quarantine"] == "CERTIFIED_ISOLATED"

    summary = artifact["simulation_summary"]
    assert summary["total_scenarios"] == 5
    assert summary["scenarios_passed"] == 5
    assert summary["all_scenarios_passed"] is True

    # Validate against disk content
    with open(artifact_file, "r", encoding="utf-8") as f:
        disk_data = json.load(f)
    assert disk_data == artifact

    invariants = artifact["invariants_verified"]
    assert invariants["zero_steady_state_error"] is True
    assert invariants["anti_windup_clamping_active"] is True
    assert invariants["fail_safe_deenergize_on_trip"] is True
    assert invariants["schmitt_trigger_hysteresis_anti_chatter"] is True
    assert invariants["multi_rate_numerical_stability"] is True
    assert invariants["no_master_thrash"] is True


# ============================================================================
# 5. Anti-Straton & Fail-Closed Hardware Safety Verification
# ============================================================================


def test_safety_and_anti_straton_invariants() -> None:
    """Verify zero physical hardware leaks and zero Copa-Data Straton dependencies."""
    import inspect
    import jev_cscape.simulation.verifier as verifier_mod

    source = inspect.getsource(verifier_mod)

    # Invariant: Zero COM ports
    assert "COM1" not in source
    assert "COM2" not in source
    assert "\\\\.\\COM" not in source

    # Invariant: Zero Win32 download command IDs
    assert "32827" not in source
    assert "33149" not in source

    # Invariant: Zero Straton runtime references
    assert "T5SIMUL" not in source
    assert "T5RTI" not in source
    assert "K5DBXS" not in source
