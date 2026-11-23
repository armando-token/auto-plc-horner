"""Unit and integration tests for CLI stress & concurrency benchmark harness."""

import json
from pathlib import Path
import pytest

from scripts.cli_stress_benchmark import (
    CliStressBenchmarkSuite,
    create_sample_st_file,
    execute_subcommand_monitored,
    get_default_command_map,
    main,
    validate_contract_payload,
)


def test_benchmark_covers_all_required_subcommands(tmp_path):
    """Verify benchmark defines all 8 required CLI subcommands."""
    st_file = tmp_path / "test.st"
    st_file.write_text("PROGRAM P\nEND_PROGRAM\n", encoding="utf-8")

    cmd_map = get_default_command_map(st_file, quick=True)
    required = {
        "doctor",
        "status",
        "validate-st",
        "simulate",
        "inspect-registers",
        "audit-safety",
        "soak",
        "scale-point",
    }
    assert set(cmd_map.keys()) == required
    for subcmd in required:
        assert "--json" in cmd_map[subcmd]


def test_validate_contract_payload_compliance():
    """Verify validate_contract_payload enforces 4-state contract integrity."""
    # Compliant success
    valid_payload = {
        "status": "success",
        "error_code": None,
        "details": "All checks passed.",
        "data": {"count": 10},
    }
    valid, status, err = validate_contract_payload(valid_payload)
    assert valid is True
    assert status == "success"
    assert err is None

    # Invalid status
    invalid_status = {
        "status": "UNKNOWN_STATUS",
        "details": "Some details",
        "data": {},
    }
    valid, status, err = validate_contract_payload(invalid_status)
    assert valid is False

    # Subjective status term
    subjective_payload = {
        "status": "VERIFIED",
        "details": "Subjective status test",
        "data": {},
    }
    valid, status, err = validate_contract_payload(subjective_payload)
    assert valid is False

    # Missing details
    missing_details = {
        "status": "success",
        "data": {},
    }
    valid, status, err = validate_contract_payload(missing_details)
    assert valid is False


def test_execute_single_subcommand_monitored():
    """Verify execution of single CLI subcommand captures telemetry and satisfies contract."""
    telemetry = execute_subcommand_monitored(
        subcommand="doctor",
        cli_args=["doctor", "--json"],
        timeout_s=15.0,
    )
    assert telemetry.clean_exit is True
    assert telemetry.exit_code == 0
    assert telemetry.wall_duration_ms > 0
    assert telemetry.peak_rss_mb > 0
    assert telemetry.contract_valid is True
    assert telemetry.contract_status == "success"
    assert telemetry.timed_out is False


def test_concurrent_execution_4_workers(tmp_path):
    """Verify concurrent runner executes 4 parallel processes with clean exits and zero deadlocks."""
    st_file = create_sample_st_file(tmp_path / "valid.st")
    cmd_map = get_default_command_map(st_file, quick=True)

    suite = CliStressBenchmarkSuite(
        iterations=1,
        concurrency=4,
        quick=True,
        timeout_s=45.0,
    )

    concurrent_metrics = suite.run_concurrent_phase(cmd_map)

    assert concurrent_metrics["concurrency_level"] == 4
    assert concurrent_metrics["zero_mutex_deadlocks"] is True
    assert concurrent_metrics["total_deadlocks_detected"] == 0
    assert len(concurrent_metrics["waves"]) >= 2

    for wave in concurrent_metrics["waves"]:
        assert wave["concurrency"] == 4
        assert wave["all_exit_codes_zero"] is True
        assert wave["all_clean_exits"] is True
        assert wave["all_contracts_valid"] is True
        assert wave["deadlock_detected"] is False
        assert wave["temporal_overlap_detected"] is True
        assert len(wave["processes"]) == 4


def test_suite_quick_run_and_artifact_export(tmp_path):
    """Verify complete benchmark suite execution, report export, and strict contract output."""
    output_report = tmp_path / "cli_stress_report.json"

    suite = CliStressBenchmarkSuite(
        iterations=1,
        concurrency=4,
        quick=True,
        timeout_s=25.0,
        output_file=output_report,
    )

    result = suite.run_benchmark()

    # Check 4-state contract response
    assert result["status"] == "success"
    assert result["error_code"] is None
    assert "CLI stress and concurrency benchmark passed" in result["details"]
    assert result["data"]["zero_deadlocks"] is True
    assert result["data"]["total_executions"] == 16
    assert result["data"]["invariants"]["all_8_subcommands_benchmarked"] is True
    assert result["data"]["invariants"]["zero_mutex_deadlocks"] is True
    assert result["data"]["invariants"]["strict_4_state_contract_conformance"] is True

    # Check exported JSON report file
    assert output_report.exists()
    with open(output_report, "r", encoding="utf-8") as f:
        report_data = json.load(f)

    assert report_data["suite_title"] == "JEV Cscape Agent CLI Stress and Concurrency Benchmark"
    assert report_data["summary"]["zero_mutex_deadlocks"] is True
    assert report_data["summary"]["clean_termination_rate"] == 1.0
    assert report_data["summary"]["contract_conformance_rate"] == 1.0
    assert len(report_data["sequential_benchmarks"]) == 8
    assert len(report_data["concurrent_benchmarks"]["waves"]) >= 2


def test_main_cli_runner(tmp_path, capsys):
    """Verify main() entrypoint executes with --quick --json flags."""
    output_report = tmp_path / "cli_report_main.json"
    exit_code = main(["--quick", "--concurrency", "4", "--output", str(output_report), "--json"])
    assert exit_code == 0

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["zero_deadlocks"] is True
    assert output_report.exists()
