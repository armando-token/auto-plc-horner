"""Comprehensive Unit Test Suite for Air-Gapped Bundle Verification & Gate G5 Signoff.

Work Package: W024 (Gate G5)
Classification: PRODUCTION_READY

Validates:
1. Stage 1 (Environment): Host platform and Python runtime conformance.
2. Stage 2 (Hardware Lockout): Full fail-closed interception of ports, flash tools, and download commands.
3. Stage 3 (Straton Quarantine): Zero active Copa-Data Straton runtime dependencies in src/.
4. Stage 4 (Manifest Integrity): SHA-256 match for all registered artifacts.
5. Stage 5 (Simulation Smoke): In-memory closed-loop scan execution without faults.
6. Stage 6 (Ops Consistency): Backlog and gates ledger completeness and consistency.
7. Full runner: End-to-end execution and signoff evidence artifact export.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from scripts.verify_bundle import (
    run_full_bundle_verification,
    verify_stage_environment,
    verify_stage_hardware_lockout,
    verify_stage_manifest_integrity,
    verify_stage_ops_consistency,
    verify_stage_simulation_smoke,
    verify_stage_straton_quarantine,
)


def test_verify_stage_environment() -> None:
    """Verify environment stage reports passed status and python version."""
    res = verify_stage_environment()
    assert res["stage"] == "environment"
    assert res["status"] == "passed"
    assert "python_version" in res


def test_verify_stage_hardware_lockout() -> None:
    """Verify hardware lockout stage enforces all 11 restricted security checks."""
    res = verify_stage_hardware_lockout()
    assert res["stage"] == "hardware_lockout"
    assert res["status"] == "passed"
    assert res["lockouts_tested"] == 11
    assert res["lockouts_enforced"] == 11


def test_verify_stage_straton_quarantine() -> None:
    """Verify Straton quarantine stage detects zero banned runtime references."""
    res = verify_stage_straton_quarantine()
    assert res["stage"] == "straton_quarantine"
    assert res["status"] == "passed"
    assert len(res["violations"]) == 0


def test_verify_stage_manifest_integrity() -> None:
    """Verify manifest integrity stage checks all hashes against disk."""
    res = verify_stage_manifest_integrity()
    assert res["stage"] == "manifest_integrity"
    assert res["status"] == "passed"
    assert res["error_count"] == 0
    assert len(res["errors"]) == 0


def test_verify_stage_simulation_smoke() -> None:
    """Verify simulation smoke stage executes 100 scans with bounded level."""
    res = verify_stage_simulation_smoke()
    assert res["stage"] == "simulation_smoke"
    assert res["status"] == "passed"
    assert res["scans_executed"] == 100
    assert res["virtual_time_ms"] == 1000.0
    assert 0.0 <= res["final_level_pv"] <= 100.0
    assert res["engine_state"] == "RUNNING"


def test_verify_stage_ops_consistency() -> None:
    """Verify operations consistency stage validates work packages and gates."""
    res = verify_stage_ops_consistency()
    assert res["stage"] == "ops_consistency"
    assert res["status"] == "passed"
    assert res["work_packages_tracked"] >= 24
    assert res["gates_tracked"] >= 6


def test_run_full_bundle_verification(tmp_path: Path) -> None:
    """Verify full bundle verification passes and exports valid signoff evidence."""
    signoff_file = tmp_path / "test_signoff_evidence.json"
    passed, signoff = run_full_bundle_verification(output_signoff_path=signoff_file)

    assert passed is True
    assert signoff_file.is_file()
    assert signoff["gate"] == "G5"
    assert signoff["work_package"] == "W024"
    assert signoff["status"] == "success"
    assert signoff["classification"] == "FINAL_SIGNOFF_PASSED"
    assert signoff["total_stages"] == 6
    assert signoff["stages_passed"] == 6

    with open(signoff_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["verdict"] == signoff["verdict"]
