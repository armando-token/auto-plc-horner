"""Comprehensive Unit & Integration Test Suite for Closed-Loop Pilot Demonstration.

Work Package: PILOT_DEMONSTRATION (Gate G12 Pilot Delivery)
Classification: PRODUCTION_READY [Deterministic Multi-Disciplinary Pilot]

Validates:
1. scripts.run_pilot_demonstration.run_pilot_demonstration executes cleanly and returns
   a strict 4-state contract (status: success, error_code: null, details: str, data: dict).
2. IEC 61131-3 Structured Text POU validation and aggressive ladder construct rejection.
3. SimulationEngine closed-loop regulation with TwoTankCascadeModel and ClosedLoopPIController.
4. ModbusScalingBridge telemetry scaling and quality word tracking.
5. ISA-18.2 alarm event monitoring with Schmitt-trigger hysteresis.
6. Recipe parameter download into %R registers with bit-exact verification.
7. FastMCP JSON-RPC 2.0 tool dispatch (tools/call for cscape_status and sim_inspect_registers).
8. Strict zero memory leakage (< 100KB heap growth) and zero hardware leakage assertions.
9. Deterministic report artifact export to artifacts/pilot/pilot_demonstration_report.json.
10. CLI main entry point execution with exit code 0.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.simulation.engine import SimulationEngine
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from scripts.run_pilot_demonstration import (
    PILOT_RECIPE_DATA,
    PILOT_ST_POU_CODE,
    audit_hardware_safety_invariants,
    dispatch_fastmcp_tools,
    download_recipe_to_registers,
    init_modbus_scaling_bridge,
    main,
    run_pilot_demonstration,
    validate_st_pou_code,
)


def test_pilot_demonstration_full_run_contract(tmp_path: Path) -> None:
    """Verify end-to-end pilot demonstration executes cleanly and returns strict 4-state contract."""
    report_file = tmp_path / "pilot_demonstration_report.json"

    result = run_pilot_demonstration(
        cycles=2000,
        dt_ms=10.0,
        output_path=str(report_file),
        repo_root_override=tmp_path,
        seed=42,
    )

    # 1. Strict 4-state engineering contract envelope
    assert isinstance(result, dict)
    assert result["status"] in ("success", "failed", "blocked", "inconclusive")
    assert result["status"] == "success"
    assert result["error_code"] is None
    assert isinstance(result["details"], str)
    assert len(result["details"]) > 0
    assert isinstance(result["data"], dict)

    data = result["data"]

    # 2. Gate metadata and title
    assert data["gate"] == "PILOT"
    assert data["work_package"] == "PILOT_DEMONSTRATION"
    assert data["verdict"] == "success"
    assert "timestamp_utc" in data
    assert data["duration_s"] > 0

    # 3. All 11 engineering invariants verified
    invariants = data["invariants_verified"]
    expected_invariants = [
        "iec_61131_3_pure_st_syntax",
        "forbidden_ladder_rejection",
        "two_tank_mass_conservation",
        "closed_loop_setpoint_tracking",
        "stochastic_disturbance_rejection",
        "modbus_scaling_telemetry_valid",
        "isa_18_2_alarm_monitoring_active",
        "recipe_download_to_r_verified",
        "fastmcp_jsonrpc_dispatch_passed",
        "zero_memory_leak_lt_100kb",
        "zero_hardware_leakage",
    ]
    for inv in expected_invariants:
        assert inv in invariants, f"Missing invariant: {inv}"
        assert invariants[inv] is True, f"Invariant failed: {inv}"

    # 4. Verify subsystems payloads
    subsystems = data["subsystems"]
    assert "st_validation" in subsystems
    assert "simulation" in subsystems
    assert "modbus_bridge" in subsystems
    assert "recipe" in subsystems
    assert "isa_alarms" in subsystems
    assert "fastmcp_dispatch" in subsystems
    assert "memory_telemetry" in subsystems
    assert "hardware_safety" in subsystems

    # Simulation metrics verification
    sim = subsystems["simulation"]
    assert sim["cycles_executed"] == 2000
    assert sim["mass_balance_error"] < 1e-4
    assert sim["tank1_mass_balance_error"] < 1e-4
    assert sim["tank2_mass_balance_error"] < 1e-4
    assert sim["steady_state_error_pct"] < 10.0
    assert len(sim["periodic_snapshots"]) >= 10

    # Memory telemetry verification
    mem = subsystems["memory_telemetry"]
    assert mem["zero_memory_leak_verified"] is True
    assert mem["tracemalloc_current_kb"] < 100.0

    # Hardware safety verification
    hw = subsystems["hardware_safety"]
    assert hw["zero_hardware_leakage_verified"] is True
    assert hw["com_ports_blocked"] >= 256
    assert hw["flasher_binaries_blocked"] == 4
    assert hw["download_commands_blocked"] == 2

    # 5. Verify exported JSON artifact
    assert report_file.exists(), f"Report file not written: {report_file}"
    file_content = json.loads(report_file.read_text(encoding="utf-8"))
    assert file_content["verdict"] == "success"
    assert file_content["status"] == "success"
    assert file_content["gate"] == "PILOT"


def test_iec_st_pou_validation_and_ladder_rejection() -> None:
    """Verify IEC 61131-3 Structured Text parsing and aggressive rejection of ladder logic constructs."""
    st_info = validate_st_pou_code()

    assert st_info["status"] == "success"
    assert st_info["pou_name"] == "PilotTwoTankLevelControl"
    assert st_info["pou_type"] == "PROGRAM"
    assert st_info["syntax_valid"] is True
    assert st_info["variables_count"] == 17
    assert st_info["bound_registers_count"] == 16
    assert "%AI1" in st_info["bound_registers"]
    assert "%AI2" in st_info["bound_registers"]
    assert "%AQ1" in st_info["bound_registers"]
    assert "%AQ2" in st_info["bound_registers"]
    assert "%R1" in st_info["bound_registers"]
    assert "%M1" in st_info["bound_registers"]
    assert st_info["ladder_rejection_tested"] is True


def test_modbus_telemetry_scaling_bridge_integrity() -> None:
    """Verify ModbusScalingBridge point mappings, scaling conversions, and quality flags."""
    bridge = init_modbus_scaling_bridge()
    points = bridge.points

    assert len(points) == 5
    assert "TANK1_LEVEL" in points
    assert "TANK2_LEVEL" in points
    assert "INFLOW_RATE1" in points
    assert "INLET_VALVE_CMD" in points
    assert "DISCHARGE_VALVE_CMD" in points

    # Test Tank 1 Level (%AI1, 0..100% -> 0..32000 counts)
    pt_level1 = bridge.get_point("TANK1_LEVEL")
    assert pt_level1 is not None
    assert pt_level1.channel == "%AI1"
    assert pt_level1.modbus_address == 30001

    # 16000 counts == 50.0%
    eu_val, qc, qw = pt_level1.raw_to_eu(16000)
    assert pytest.approx(eu_val, abs=1e-2) == 50.0
    assert qc.value == "GOOD"
    assert (qw & 0x00C0) == 0x00C0

    # Reverse: 50.0% == 16000 counts
    raw_val, _, _ = pt_level1.eu_to_raw(50.0)
    assert raw_val == 16000

    # Test Valve Command (%AQ1, holding register 40001)
    pt_valve = bridge.get_point("INLET_VALVE_CMD")
    assert pt_valve is not None
    assert pt_valve.channel == "%AQ1"
    assert pt_valve.modbus_address == 40001


def test_recipe_download_r_registers_integrity() -> None:
    """Verify recipe download to %R registers and bit-exact readback verification."""
    engine = SimulationEngine(default_dt_ms=10.0, record_trace=False)
    recipe_res = download_recipe_to_registers(engine)

    assert recipe_res["download_verified"] is True
    assert recipe_res["recipe_id"] == 1
    assert recipe_res["registers_written_count"] == 10
    assert recipe_res["registers_verified_count"] == 10

    # Verify individual recipe registers
    for reg, expected_val in PILOT_RECIPE_DATA.items():
        assert engine.registers.read_word(reg) == expected_val


def test_isa182_alarm_monitoring_ledger(tmp_path: Path) -> None:
    """Verify ISA-18.2 alarm events (Low Level and High Level) trip and clear with Schmitt-trigger hysteresis."""
    report_file = tmp_path / "alarm_test_report.json"
    result = run_pilot_demonstration(
        cycles=2000,
        output_path=str(report_file),
        repo_root_override=tmp_path,
    )
    assert result["status"] == "success"

    alarms_subsystem = result["data"]["subsystems"]["isa_alarms"]
    events = alarms_subsystem["events"]

    assert len(events) >= 2
    types_found = {ev["alarm_type"] for ev in events}
    states_found = {ev["state"] for ev in events}

    assert "LOW_LEVEL" in types_found
    assert "HIGH_LEVEL" in types_found
    assert "TRIPPED" in states_found
    assert "CLEARED" in states_found

    # Verify deadband hysteresis: cleared thresholds differ from trip thresholds
    for ev in events:
        if ev["alarm_type"] == "LOW_LEVEL" and ev["state"] == "TRIPPED":
            assert ev["threshold_pct"] == 25.0
        elif ev["alarm_type"] == "LOW_LEVEL" and ev["state"] == "CLEARED":
            assert ev["threshold_pct"] == 27.0
        elif ev["alarm_type"] == "HIGH_LEVEL" and ev["state"] == "TRIPPED":
            assert ev["threshold_pct"] == 70.0
        elif ev["alarm_type"] == "HIGH_LEVEL" and ev["state"] == "CLEARED":
            assert ev["threshold_pct"] == 68.0


def test_fastmcp_tool_dispatch_parity() -> None:
    """Verify FastMCP JSON-RPC 2.0 tool dispatch for cscape_status and sim_inspect_registers."""
    dispatch_res = dispatch_fastmcp_tools()

    assert dispatch_res["all_calls_successful"] is True
    assert "cscape_status" in dispatch_res["tools_dispatched"]
    assert "sim_inspect_registers" in dispatch_res["tools_dispatched"]

    status_data = dispatch_res["cscape_status_result"]
    assert status_data["status"] == "success"
    assert "agent_version" in status_data["data"]
    assert "gates_summary" in status_data["data"]

    inspect_data = dispatch_res["sim_inspect_registers_result"]
    assert inspect_data["status"] == "success"
    assert "count" in inspect_data["data"]


def test_hardware_safety_lockout_audit() -> None:
    """Verify fail-closed hardware lockout across all COM ports, flasher binaries, and Win32 download commands."""
    hw_audit = audit_hardware_safety_invariants()

    assert hw_audit["zero_hardware_leakage_verified"] is True
    assert hw_audit["com_ports_tested"] == hw_audit["com_ports_blocked"]
    assert hw_audit["com_ports_blocked"] >= 256
    assert hw_audit["flasher_binaries_tested"] == 4
    assert hw_audit["flasher_binaries_blocked"] == 4
    assert hw_audit["download_commands_tested"] == 2
    assert hw_audit["download_commands_blocked"] == 2


def test_cli_main_invocation(tmp_path: Path) -> None:
    """Verify CLI main entry point runs cleanly and exits with code 0."""
    report_file = tmp_path / "cli_pilot_report.json"
    exit_code = main(["--cycles", "2000", "--output", str(report_file)])

    assert exit_code == 0
    assert report_file.exists()
    payload = json.loads(report_file.read_text(encoding="utf-8"))
    assert payload["gate"] == "PILOT"
    assert payload["verdict"] == "success"
    assert payload["status"] == "success"
