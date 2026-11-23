"""Tests for CLI Long-Term Soak & Tracemalloc Profiler (Gate G10, W045)."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from scripts.run_cli_soak_profile import CliSoakProfiler, run_cli_soak_profile


def test_cli_soak_profiler_execution() -> None:
    """Verify CliSoakProfiler runs a fast 10-iteration soak without errors."""
    profiler = CliSoakProfiler(iterations=10, memory_budget_kb=150.0)
    res = profiler.run_soak()

    assert res.status == AgentStatus.SUCCESS
    assert res.data["total_iterations"] == 10
    assert res.data["failed_iterations"] == 0
    assert res.data["is_memory_leak_free"] is True
    assert res.data["average_latency_ms"] > 0.0


def test_cli_soak_script_artifact_export(tmp_path: Path) -> None:
    """Verify script runner writes valid json report."""
    res = run_cli_soak_profile(repo_root=tmp_path, iterations=12)

    assert res.status == AgentStatus.SUCCESS
    out_file = tmp_path / "artifacts" / "benchmarks" / "cli_soak_profile.json"
    assert out_file.exists()

    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["work_package"] == "W045"
    assert data["gate"] == "G10"
    assert data["result"]["status"] == "success"
    assert data["result"]["data"]["total_iterations"] == 12
