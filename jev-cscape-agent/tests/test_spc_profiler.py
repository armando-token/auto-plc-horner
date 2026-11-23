"""Unit and integration test suite for Statistical Process Control (SPC) & Cpk Capability Profiler.

Work Package: W054 (Gate G10 / G4)
Classification: TEST [in-process statistical stability & capability diagnostics]
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.spc_profiler import (
    ShewhartControlLimits,
    SPCMetrics,
    SPCProfiler,
    WesternElectricViolations,
)
from scripts.run_spc_profiler_verification import run_spc_profiler_verification


def test_spc_profiler_initialization_and_validation() -> None:
    # Valid
    p = SPCProfiler(usl=100.0, lsl=0.0, window_size=50)
    assert p.usl == 100.0
    assert p.lsl == 0.0
    assert p.target == 50.0

    # Invalid USL <= LSL
    with pytest.raises(ValueError):
        SPCProfiler(usl=50.0, lsl=50.0)

    with pytest.raises(ValueError):
        SPCProfiler(usl=40.0, lsl=50.0)

    # Invalid window size < 10
    with pytest.raises(ValueError):
        SPCProfiler(usl=100.0, lsl=0.0, window_size=5)


def test_spc_profiler_in_control_capability() -> None:
    # Centered process around 50.0, USL=60, LSL=40, width=20.
    # Sigma ~ 1.0 -> 6*sigma = 6 -> Cp = 20 / 6 = 3.33
    p = SPCProfiler(usl=60.0, lsl=40.0, target=50.0, window_size=40)
    samples = [50.0 + (i % 5 - 2) * 0.5 for i in range(40)]
    p.ingest_batch(samples)

    metrics = p.compute_metrics()
    assert metrics is not None
    assert metrics.capability is not None
    assert metrics.capability.cp > 2.0
    assert metrics.capability.cpk > 2.0
    assert metrics.capability.is_capable_133 is True
    assert metrics.capability.is_capable_167 is True
    assert metrics.violations.any_violation is False


def test_western_electric_rule1_beyond_3sigma() -> None:
    p = SPCProfiler(usl=60.0, lsl=40.0, window_size=30)
    # Baseline with mean=50.0, sigma~1.0
    p.ingest_batch([50.0 + (i % 3 - 1) * 0.8 for i in range(25)])

    # Inject extreme value
    p.ingest_sample(58.0)
    m = p.compute_metrics()
    assert m is not None
    assert m.violations.rule1_beyond_3sigma is True
    assert m.violations.any_violation is True


def test_western_electric_rule2_zone_a() -> None:
    p = SPCProfiler(usl=60.0, lsl=40.0, window_size=30)
    p.ingest_batch([50.0 for _ in range(20)])

    # Inject 2 of 3 points at +2.5 sigma
    # Note: with baseline variance low, a jump to 52.5 is >> 2 sigma
    p.ingest_sample(50.0)
    p.ingest_sample(53.0)
    p.ingest_sample(50.1)
    p.ingest_sample(53.2)

    m = p.compute_metrics()
    assert m is not None
    assert m.violations.rule2_zone_a is True


def test_western_electric_rule3_zone_b() -> None:
    p = SPCProfiler(usl=60.0, lsl=40.0, window_size=30)
    # Baseline
    p.ingest_batch([50.0 + (i % 3 - 1) * 0.5 for i in range(20)])

    # Inject 4 of 5 points beyond 1-sigma on upper side
    p.ingest_sample(51.8)
    p.ingest_sample(51.9)
    p.ingest_sample(50.2)
    p.ingest_sample(51.7)
    p.ingest_sample(52.0)

    m = p.compute_metrics()
    assert m is not None
    assert m.violations.rule3_zone_b is True


def test_western_electric_rule4_mean_shift() -> None:
    p = SPCProfiler(usl=60.0, lsl=40.0, window_size=30)
    # 8 consecutive points strictly above mean
    p.ingest_batch([50.0 + (i % 2) * 0.2 - 0.1 for i in range(15)])
    for _ in range(8):
        p.ingest_sample(50.8)

    m = p.compute_metrics()
    assert m is not None
    assert m.violations.rule4_mean_shift is True


def test_spc_zero_variance_guard() -> None:
    p = SPCProfiler(usl=60.0, lsl=40.0, window_size=20)
    # All identical values (zero moving range)
    p.ingest_batch([50.0 for _ in range(20)])

    m = p.compute_metrics()
    assert m is not None
    assert m.capability is not None
    # Should not raise ZeroDivisionError
    assert m.capability.cp == 99.99
    assert m.capability.cpk == 99.99


def test_spc_horner_register_sync() -> None:
    reg_table = RegisterTable()
    p = SPCProfiler(usl=60.0, lsl=40.0, window_size=30)
    p.ingest_batch([50.0 + (i % 3 - 1) * 0.6 for i in range(25)])

    metrics = p.sync_to_registers(reg_table)
    assert metrics is not None

    r210 = reg_table.read_word("%R210")
    r211 = reg_table.read_word("%R211")
    r212 = reg_table.read_word("%R212")
    r213 = reg_table.read_word("%R213")
    m25 = reg_table.read_bit("%M25")

    assert r210 > 0
    assert r211 > 0
    assert r212 == int(round(metrics.mean * 10.0))
    assert r213 > 0
    assert m25 == metrics.violations.rule1_beyond_3sigma


def test_spc_verification_runner_contract(tmp_path: Path) -> None:
    test_evidence_file = tmp_path / "spc_evidence_test.json"
    result = run_spc_profiler_verification(output_path=test_evidence_file)

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert result["data"]["all_passed"] is True
    assert test_evidence_file.exists()

    with open(test_evidence_file, "r", encoding="utf-8") as f:
        payload = json.load(f)
    assert payload["status"] == "success"
    assert len(payload["data"]["assertions"]) >= 6
