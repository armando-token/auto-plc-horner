"""Tests for JEV Cscape Agent CLI entrypoint and subcommand dispatch."""

import json
import pytest
from jev_cscape.cli import main, get_provider_mode


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "JEV Cscape Agent CLI" in captured.out
    assert "doctor" in captured.out
    assert "inspect" in captured.out
    assert "validate-st" in captured.out


def test_cli_no_args_prints_help(capsys):
    ret = main([])
    assert ret == 0
    captured = capsys.readouterr()
    assert "JEV Cscape Agent CLI" in captured.out


def test_cli_doctor(capsys):
    ret = main(["doctor", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["cscape_installed"] is True
    assert payload["data"]["hardware_lockout_active"] is True
    assert payload["data"]["provider_mode"]["mode"] == "offline/mock"


def test_cli_status(capsys):
    ret = main(["status", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert "gates_summary" in payload["data"]


def test_cli_sweep(capsys):
    ret = main(["sweep", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert "detected_count" in payload["data"]
    assert "dismissed_count" in payload["data"]


def test_cli_validate_st_pure(tmp_path, capsys):
    st_file = tmp_path / "valid.st"
    st_file.write_text("PROGRAM Main\nVAR\n  x : BOOL;\nEND_VAR\nx := TRUE;\nEND_PROGRAM\n", encoding="utf-8")

    ret = main(["validate-st", str(st_file), "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"


def test_cli_validate_st_ladder_forbidden(tmp_path, capsys):
    st_file = tmp_path / "invalid.st"
    st_file.write_text("PROGRAM Main\n---[ ]---\nEND_PROGRAM\n", encoding="utf-8")

    ret = main(["validate-st", str(st_file), "--json"])
    assert ret == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "failed"
    assert payload["error_code"] == "ERR_LADDER_FORBIDDEN"


def test_provider_mode_offline_when_no_key(monkeypatch):
    monkeypatch.delenv("JEV_API_KEY", raising=False)
    mode = get_provider_mode()
    assert mode["mode"] == "offline/mock"
    assert mode["has_api_key"] is False


def test_cli_inspect_navigator_mock(capsys):
    ret = main(["inspect-navigator", "--mock", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["mode"] == "offline/mock"
    assert payload["data"]["pane_info"]["pane_found"] is True
    assert payload["data"]["pane_info"]["tree_class"] == "SysTreeView32"
    assert payload["data"]["pane_info"]["tree_auto_id"] == "300"


def test_cli_compile_mock(capsys):
    ret = main(["compile", "--mock", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["mode"] == "offline/mock"
    assert payload["data"]["compilation"]["success"] is True
    assert payload["data"]["compilation"]["command_id"] == 32826
    assert payload["data"]["compilation"]["errors_count"] == 0


def test_cli_scrape_output_mock(capsys):
    ret = main(["scrape-output", "--mock", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["mode"] == "offline/mock"
    assert payload["data"]["error_count"] == 0
    assert payload["data"]["warning_count"] == 0
    assert payload["data"]["report"]["is_clean"] is True


def test_cli_simulate(tmp_path, capsys):
    trace_path = tmp_path / "sim_trace.json"
    evidence_path = tmp_path / "sim_evidence.json"

    ret = main([
        "simulate",
        "--cycles", "25",
        "--dt-ms", "10.0",
        "--mock",
        "--export-trace", str(trace_path),
        "--export-evidence", str(evidence_path),
        "--json",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["cycles_executed"] == 25
    assert payload["data"]["virtual_elapsed_ms"] == 250.0
    assert payload["data"]["mode"] == "offline/mock"
    assert trace_path.exists()
    assert evidence_path.exists()


def test_cli_sim_alias(capsys):
    ret = main(["sim", "-c", "5", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["cycles_executed"] == 5


def test_cli_inspect_registers_range(capsys):
    ret = main(["inspect-registers", "-a", "%R1..%R5", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert "output_table" in payload["data"]
    assert payload["data"]["summary"]["count"] == 5
    addrs = [r["address"] for r in payload["data"]["summary"]["registers"]]
    assert addrs == ["%R1", "%R2", "%R3", "%R4", "%R5"]


def test_cli_regs_alias_json_format(capsys):
    ret = main(["regs", "-a", "%SR1..%SR3", "-f", "json", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["count"] == 3
    addrs = [r["address"] for r in payload["data"]["registers"]]
    assert addrs == ["%SR1", "%SR2", "%SR3"]


def test_cli_inspect_registers_channel_filter(capsys):
    ret = main(["registers", "-c", "%S", "-f", "json", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["count"] == 16


def test_cli_inspect_registers_invalid_range(capsys):
    ret = main(["regs", "-a", "%R10..%R2", "--json"])
    assert ret == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "failed"
    assert payload["error_code"] == "INSPECT_REGISTERS_ERROR"


def test_cli_manifest_generate(tmp_path, capsys):
    out_file = tmp_path / "cli_test_manifest.json"
    ret = main(["manifest", "-o", str(out_file), "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert "root_digest" in payload["data"]
    assert out_file.is_file()


def test_cli_manifest_verify(tmp_path, capsys):
    out_file = tmp_path / "cli_test_manifest.json"
    ret = main(["manifest", "-o", str(out_file), "--json"])
    assert ret == 0
    capsys.readouterr()  # Clear stdout from generate call

    ret_verify = main(["manifest", "-v", str(out_file), "--json"])
    assert ret_verify == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["status"] == "verified"


# ============================================================================
# Gate G11: audit-safety Subcommand Tests
# ============================================================================


def test_cli_help_includes_new_subcommands(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "audit-safety" in captured.out
    assert "soak" in captured.out
    assert "scale-point" in captured.out
    assert "ground" in captured.out


def test_cli_audit_safety_help(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["audit-safety", "--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "--export-evidence" in captured.out


def test_cli_audit_safety_json(tmp_path, capsys):
    evidence_file = tmp_path / "g11_evidence.json"
    ret = main(["audit-safety", "--json", "--export-evidence", str(evidence_file)])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["gate"] == "G11"
    assert payload["data"]["physical_ports_audit"]["all_ports_locked_out"] is True
    assert payload["data"]["flasher_binaries_audit"]["all_binaries_locked_out"] is True
    assert payload["data"]["win32_interceptor_audit"]["all_download_commands_hard_blocked"] is True
    assert payload["data"]["git_remotes_audit"]["local_only_enforced"] is True
    assert payload["data"]["mcp_isolation_audit"]["isolation_verified"] is True
    assert evidence_file.is_file()


# ============================================================================
# Gate G10: soak Subcommand Tests
# ============================================================================


def test_cli_soak_help(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["soak", "--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "--cycles" in captured.out
    assert "--rates" in captured.out
    assert "--dt-ms" in captured.out


def test_cli_soak_json(tmp_path, capsys):
    evidence_file = tmp_path / "g10_evidence.json"
    ret = main([
        "soak",
        "--dt-ms", "50.0",
        "--cycles", "500",
        "--json",
        "--export-evidence", str(evidence_file),
    ])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["gate"] == "G10"
    assert payload["data"]["summary"]["all_rates_stable"] is True
    assert payload["data"]["summary"]["zero_memory_leak_verified"] is True
    assert payload["data"]["summary"]["zero_nan_values_verified"] is True
    assert evidence_file.is_file()


def test_cli_soak_multirate(capsys):
    ret = main([
        "soak",
        "--rates", "20,50",
        "--cycles", "2000",
        "--json",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["summary"]["all_rates_stable"] is True
    assert "20ms" in payload["data"]["rate_metrics"]
    assert "50ms" in payload["data"]["rate_metrics"]


# ============================================================================
# Gate G8: scale-point Subcommand Tests
# ============================================================================


def test_cli_scale_point_help(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["scale-point", "--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "--channel" in captured.out
    assert "--raw" in captured.out
    assert "--eu" in captured.out


def test_cli_scale_point_default(capsys):
    ret = main(["scale-point", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["channel"] == "%AI1"
    assert payload["data"]["raw_value"] == 16000
    assert payload["data"]["eu_value"] == 50.0
    assert payload["data"]["quality"] == "GOOD"
    assert payload["data"]["round_trip_error"] == 0


def test_cli_scale_point_raw_to_eu(capsys):
    ret = main(["scale-point", "--channel", "%AI1", "--raw", "8000", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["raw_value"] == 8000
    assert payload["data"]["eu_value"] == 25.0
    assert payload["data"]["quality"] == "GOOD"
    assert payload["data"]["round_trip_error"] == 0


def test_cli_scale_point_eu_to_raw(capsys):
    ret = main(["scale-point", "--channel", "%AQ1", "--eu", "75.0", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["channel"] == "%AQ1"
    assert payload["data"]["raw_value"] == 24000
    assert payload["data"]["eu_value"] == 75.0
    assert payload["data"]["quality"] == "GOOD"


def test_cli_scale_point_alias_scale(capsys):
    ret = main(["scale", "--raw", "32000", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["eu_value"] == 100.0


def test_cli_scale_point_custom_transmitter(capsys):
    ret = main([
        "scale-point",
        "--channel", "%AI2",
        "--raw", "16000",
        "--eu-min", "0",
        "--eu-max", "150",
        "--unit", "psi",
        "--json",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["eu_value"] == 75.0
    assert payload["data"]["eu_unit"] == "psi"
    assert payload["data"]["quality"] == "GOOD"


def test_cli_scale_point_invalid_range(capsys):
    ret = main(["scale-point", "--raw-min", "100", "--raw-max", "50", "--json"])
    assert ret == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "failed"
    assert payload["error_code"] == "INVALID_RANGE_SPAN"


def test_cli_scale_point_ieee754(capsys):
    ret = main(["scale-point", "--raw", "16000", "--ieee754", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert payload["data"]["is_32bit_float"] is True
    assert len(payload["data"]["modbus_words"]) == 2


# ============================================================================
# Gate G9: ground / vision Subcommand Tests
# ============================================================================


def test_cli_ground_help(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["ground", "--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "--image" in captured.out


def test_cli_ground_execution(capsys):
    ret = main(["ground", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert "regions" in payload["data"]
    assert len(payload["data"]["regions"]) == 5
    assert "fallback_controls" in payload["data"]
    assert "ribbon_error_check" in payload["data"]["fallback_controls"]


def test_cli_ground_alias_vision(capsys):
    ret = main(["vision", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "success"
    assert "status_bar" in payload["data"]["regions"]






