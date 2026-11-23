"""Unit tests asserting Gate G10 Multi-Rate Closed-Loop Long-Term Soak Verification.

Work Package: W029 (Gate G10)
Classification: TESTED_MOCK [offline/DEV only]

Validates:
1. Fast soak execution (1,000 cycles) across multiple rates (5ms, 10ms, 20ms, 50ms).
2. Memory telemetry capture via tracemalloc and psutil with zero memory leak (< 100KB).
3. Bounded level tracking (steady-state error <= 1.0%), zero NaN values, and zero numerical divergence.
4. Deterministic evidence artifact export and schema conformance.
5. Strict 4-state engineering contract return payload.
6. RegisterTable integration and channel binding invariants.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.simulation.engine import SimulationEngine
from jev_cscape.simulation.register_table import RegisterTable
from jev_cscape.simulation.soak import (
    SoakMemoryMetrics,
    SoakRateMetrics,
    SoakVerifier,
)
from scripts.soak_verifier import main, run_soak_verification


def test_soak_runner_fast_execution(tmp_path: Path) -> None:
    """Verify fast soak runner execution over 1,000 cycles across all scan rates."""
    evidence_path = tmp_path / "soak_test_fast.json"
    verifier = SoakVerifier(total_cycles=1000, scan_rates_ms=[5.0, 10.0, 20.0, 50.0])

    res = verifier.run_soak(export_evidence=evidence_path)

    assert res.status == AgentStatus.SUCCESS
    assert res.error_code is None
    data = res.data

    # Check cycles and rates
    assert data["summary"]["total_cycles_executed"] == 1000
    assert data["summary"]["rates_tested_count"] == 4
    assert data["summary"]["all_rates_stable"] is True
    assert data["summary"]["total_nan_count"] == 0
    assert data["summary"]["total_divergence_count"] == 0

    # Check level tracking bounds
    assert data["summary"]["max_steady_state_error"] <= 1.0

    # Check each rate metric
    for rate_key in ["5ms", "10ms", "20ms", "50ms"]:
        assert rate_key in data["rate_metrics"]
        rm = data["rate_metrics"][rate_key]
        assert rm["cycles_executed"] == 250
        assert rm["steady_state_error"] <= 1.0
        assert rm["nan_count"] == 0
        assert rm["divergence_count"] == 0
        assert rm["is_stable"] is True
        assert 0.0 <= rm["final_pv"] <= 100.0

        # Assert jitter and cycle time metrics are computed and recorded
        assert "min_cycle_time_ms" in rm
        assert "max_cycle_time_ms" in rm
        assert "mean_cycle_time_ms" in rm
        assert "jitter_p99_ms" in rm
        assert rm["min_cycle_time_ms"] > 0.0
        assert rm["max_cycle_time_ms"] >= rm["min_cycle_time_ms"]
        assert rm["min_cycle_time_ms"] <= rm["mean_cycle_time_ms"] <= rm["max_cycle_time_ms"]
        assert rm["jitter_p99_ms"] >= 0.0
        assert rm["jitter_p99_ms"] <= rm["max_cycle_time_ms"]


def test_memory_telemetry_capture(tmp_path: Path) -> None:
    """Verify memory telemetry via tracemalloc & psutil confirms zero leak (< 100KB heap growth)."""
    evidence_path = tmp_path / "mem_test.json"
    verifier = SoakVerifier(total_cycles=1000)

    res = verifier.run_soak(export_evidence=evidence_path)
    assert res.status == AgentStatus.SUCCESS

    mem = res.data["memory_telemetry"]
    assert "tracemalloc_heap_growth_kb" in mem
    assert "tracemalloc_peak_kb" in mem
    assert "tracemalloc_current_kb" in mem
    assert "psutil_rss_before_bytes" in mem
    assert "psutil_rss_after_bytes" in mem
    assert "psutil_rss_growth_kb" in mem
    assert "zero_memory_leak_verified" in mem

    assert mem["zero_memory_leak_verified"] is True
    assert mem["tracemalloc_heap_growth_kb"] < 100.0
    assert mem["psutil_rss_before_bytes"] > 0
    assert mem["psutil_rss_after_bytes"] > 0


def test_evidence_json_export_and_invariants(tmp_path: Path) -> None:
    """Verify exported JSON artifact schema, Gate G10 metadata, and invariant proofs."""
    evidence_path = tmp_path / "soak_verification_evidence.json"
    verifier = SoakVerifier(total_cycles=1000)

    res = verifier.run_soak(export_evidence=evidence_path)
    assert res.status == AgentStatus.SUCCESS
    assert evidence_path.exists()

    content = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert content["gate"] == "G10"
    assert content["work_package"] == "W029"
    assert content["status"] == "success"
    assert content["verdict"] == "success"
    assert content["mode"] == "offline/mock"
    assert content["classification"] == "TESTED_MOCK [offline/DEV only]"
    assert "timestamp_utc" in content

    invariants = content["invariants_verified"]
    assert invariants["multi_rate_stability"] is True
    assert invariants["bounded_level_tracking_le_1pct"] is True
    assert invariants["zero_memory_leak_lt_100kb"] is True
    assert invariants["zero_nan_values"] is True
    assert invariants["zero_numerical_divergence"] is True
    assert invariants["zero_jitter_overflow"] is True
    assert invariants["fail_safe_actuator_bounds"] is True
    assert invariants["hardware_lockout_active"] is True


def test_run_soak_verification_contract_response(tmp_path: Path) -> None:
    """Verify scripts.soak_verifier.run_soak_verification returns strict 4-state contract dictionary."""
    evidence_path = tmp_path / "soak_contract.json"
    response = run_soak_verification(
        total_cycles=1000,
        output_path=str(evidence_path),
        repo_root_override=tmp_path,
    )

    # Strict 4-state contract assertions
    assert response["status"] in ("success", "failed", "blocked", "inconclusive")
    assert response["status"] == "success"
    assert response["error_code"] is None
    assert isinstance(response["details"], str)
    assert len(response["details"]) > 0
    assert isinstance(response["data"], dict)
    assert "summary" in response["data"]
    assert "memory_telemetry" in response["data"]
    assert evidence_path.exists()


def test_cli_main_invocation(tmp_path: Path) -> None:
    """Verify CLI main entry point runs cleanly and exits with code 0."""
    evidence_path = tmp_path / "cli_evidence.json"
    exit_code = main(["--cycles", "1000", "--output", str(evidence_path)])

    assert exit_code == 0
    assert evidence_path.exists()
    payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert payload["gate"] == "G10"
    assert payload["summary"]["total_cycles_executed"] == 1000


def test_register_table_integration_invariant() -> None:
    """Verify RegisterTable integration and channel binding during soak evaluation."""
    verifier = SoakVerifier(total_cycles=40)
    rate_metric = verifier.run_rate_soak(dt_ms=10.0, cycles=40)

    assert rate_metric.cycles_executed == 40
    assert rate_metric.nan_count == 0
    assert rate_metric.divergence_count == 0
    assert rate_metric.is_stable is True

    # Assert SimulationEngine exposes RegisterTable directly
    engine = SimulationEngine(default_dt_ms=10.0, record_trace=False)
    assert isinstance(engine.registers, RegisterTable)
    assert engine.read_word("%AI1") == 0
    assert engine.read_word("%AQ1") == 0


def test_simulation_scan_cycle_determinism() -> None:
    """Verify Gate G10 scan cycle determinism: 100 cycles produce bit-for-bit identical tables & traces."""
    import hashlib

    def build_and_run_simulation() -> tuple[SimulationEngine, ExecutionResult]:
        engine = SimulationEngine(default_dt_ms=10.0, deterministic=True)

        # Initial conditions: inputs, registers, variables
        engine.set_input("%AI1", 16000)
        engine.set_input("%I1", True)
        engine.write_register("%R10", 42)
        engine.write_register("%R20", 100)
        engine.set_variable("MODE", "AUTOMATIC")

        # Dynamic control logic exercising I/O transformations and state accumulation
        def control_logic(eng: SimulationEngine) -> None:
            cycle = eng.cycle_count

            # First scan pulse (%S1)
            if eng.read_system_bit(1):
                eng.write_register("%R1", 999)
                eng.write_bit("%Q1", True)

            raw_ai = eng.read_register("%AI1")
            i1 = eng.read_bit("%I1")
            r10 = eng.read_register("%R10")

            if i1:
                eng.write_register("%R10", (r10 + 7) & 0xFFFF)

            # Analog and discrete outputs
            eng.write_register("%AQ1", (raw_ai // 2 + cycle) & 0xFFFF)
            eng.write_bit("%Q2", (cycle % 2) == 0)
            eng.set_variable("cycle_metric", cycle * 10.5)

        engine.register_logic_callback(control_logic)
        result = engine.run(cycles=100)
        return engine, result

    # Execute two independent simulation runs from identical initial state
    engine1, result1 = build_and_run_simulation()
    engine2, result2 = build_and_run_simulation()

    # 1. Assert identical execution results
    assert result1.status == AgentStatus.SUCCESS
    assert result2.status == AgentStatus.SUCCESS
    assert result1.data["cycles_executed"] == 100
    assert result2.data["cycles_executed"] == 100
    assert result1.data["total_cycles"] == 100
    assert result2.data["total_cycles"] == 100
    assert result1.data["virtual_elapsed_ms"] == 1000.0
    assert result2.data["virtual_elapsed_ms"] == 1000.0
    assert result1.data["sr1_scan_counter"] == 100
    assert result2.data["sr1_scan_counter"] == 100
    assert result1.data["sr5_scan_duration"] == 10
    assert result2.data["sr5_scan_duration"] == 10

    # 2. Bit-for-bit identical register tables
    reg_table1 = engine1.get_register_table()
    reg_table2 = engine2.get_register_table()
    assert reg_table1 == reg_table2
    assert engine1.registers.snapshot() == engine2.registers.snapshot()
    assert engine1.registers.committed_memory == engine2.registers.committed_memory
    assert engine1.registers.latched_inputs == engine2.registers.latched_inputs
    assert engine1.registers.system_bits == engine2.registers.system_bits
    assert engine1.registers.system_registers == engine2.registers.system_registers

    # Assert specific computed values match expected deterministic results
    assert engine1.read_register("%R1") == 999
    assert engine2.read_register("%R1") == 999
    assert engine1.read_register("%R10") == 42 + 7 * 100
    assert engine2.read_register("%R10") == 42 + 7 * 100
    assert engine1.read_register("%AQ1") == (8000 + 99) & 0xFFFF
    assert engine2.read_register("%AQ1") == (8000 + 99) & 0xFFFF
    assert engine1.read_bit("%Q1") is True
    assert engine2.read_bit("%Q1") is True
    assert engine1.read_system_bit(7) is True
    assert engine2.read_system_bit(7) is True

    # 3. Bit-for-bit identical telemetry traces across all 100 cycles
    telemetry1 = engine1.get_telemetry_trace()
    telemetry2 = engine2.get_telemetry_trace()
    assert len(telemetry1) == 100
    assert len(telemetry2) == 100
    assert telemetry1 == telemetry2

    # 4. CycleSnapshot object bit-for-bit equality and cryptographic JSON digest
    assert len(engine1.trace) == len(engine2.trace) == 100
    for idx, (snap1, snap2) in enumerate(zip(engine1.trace.snapshots, engine2.trace.snapshots)):
        assert snap1.cycle == snap2.cycle == idx
        assert snap1.time_ms == snap2.time_ms == (idx + 1) * 10.0
        assert snap1.dt_ms == snap2.dt_ms == 10.0
        assert snap1.registers == snap2.registers
        assert snap1.system_bits == snap2.system_bits
        assert snap1.system_registers == snap2.system_registers
        assert snap1.latched_inputs == snap2.latched_inputs
        assert snap1.committed_outputs == snap2.committed_outputs
        assert snap1.internal_registers == snap2.internal_registers
        assert snap1.variables == snap2.variables
        assert snap1.modified_outputs == snap2.modified_outputs
        assert snap1.diff == snap2.diff
        assert snap1 == snap2

    json1 = engine1.trace.to_json()
    json2 = engine2.trace.to_json()
    assert json1 == json2
    hash1 = hashlib.sha256(json1.encode("utf-8")).hexdigest()
    hash2 = hashlib.sha256(json2.encode("utf-8")).hexdigest()
    assert hash1 == hash2

    # 5. Bit-for-bit repeatability of closed-loop SoakVerifier process metrics
    v1 = SoakVerifier(total_cycles=100, seed=42)
    v2 = SoakVerifier(total_cycles=100, seed=42)
    metric1 = v1.run_rate_soak(dt_ms=10.0, cycles=100)
    metric2 = v2.run_rate_soak(dt_ms=10.0, cycles=100)
    wall_timing_fields = {"min_cycle_time_ms", "max_cycle_time_ms", "mean_cycle_time_ms", "jitter_p99_ms"}
    assert metric1.model_dump(exclude=wall_timing_fields) == metric2.model_dump(exclude=wall_timing_fields)


def test_jitter_metrics_accuracy_and_recording() -> None:
    """Verify jitter metrics (min, max, mean, jitter_p99_ms) are computed accurately and recorded in SoakRateMetrics."""
    verifier = SoakVerifier(total_cycles=200, scan_rates_ms=[10.0])
    metrics = verifier.run_rate_soak(dt_ms=10.0, cycles=200)

    assert isinstance(metrics, SoakRateMetrics)
    assert metrics.cycles_executed == 200
    assert metrics.min_cycle_time_ms > 0.0
    assert metrics.max_cycle_time_ms >= metrics.min_cycle_time_ms
    assert metrics.min_cycle_time_ms <= metrics.mean_cycle_time_ms <= metrics.max_cycle_time_ms
    assert metrics.jitter_p99_ms >= 0.0
    assert metrics.jitter_p99_ms <= metrics.max_cycle_time_ms
    assert metrics.nan_count == 0
    assert metrics.is_stable is True


def test_strict_zero_nan_assertion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that any NaN process variable value is trapped strictly, failing soak verification."""
    from jev_cscape.simulation.verifier import ClosedLoopPIController

    evidence_path = tmp_path / "nan_evidence.json"
    verifier = SoakVerifier(total_cycles=40, scan_rates_ms=[10.0])

    # Monkeypatch ClosedLoopPIController to inject a NaN value at step 5
    orig_execute = ClosedLoopPIController.execute
    call_count = 0

    def mock_execute(self_ctrl, ctx):
        nonlocal call_count
        call_count += 1
        orig_execute(self_ctrl, ctx)
        if call_count == 5:
            self_ctrl.last_pv_pct = float("nan")

    monkeypatch.setattr(ClosedLoopPIController, "execute", mock_execute)

    res = verifier.run_soak(export_evidence=evidence_path)

    assert res.status == AgentStatus.FAILED
    assert res.error_code == "SOAK_VERIFICATION_FAILED"
    assert "NaN values detected" in res.details
    assert res.data["summary"]["zero_nan_values_verified"] is False
    assert res.data["summary"]["total_nan_count"] >= 1
    assert res.data["invariants_verified"]["zero_nan_values"] is False


def test_strict_zero_memory_leak_threshold_assertion(tmp_path: Path) -> None:
    """Verify that exceeding the max heap growth threshold fails closed with memory leak detection."""
    evidence_path = tmp_path / "leak_evidence.json"
    # Set impossible threshold of -1.0 KB to force failure
    verifier = SoakVerifier(total_cycles=40, scan_rates_ms=[10.0], max_heap_growth_kb=-1.0)

    res = verifier.run_soak(export_evidence=evidence_path)

    assert res.status == AgentStatus.FAILED
    assert res.error_code == "SOAK_VERIFICATION_FAILED"
    assert "Memory leak detected" in res.details
    assert res.data["summary"]["zero_memory_leak_verified"] is False
    assert res.data["invariants_verified"]["zero_memory_leak_lt_100kb"] is False


def test_evidence_conforms_to_g10_schema(tmp_path: Path) -> None:
    """Verify that running run_soak with export_evidence produces valid JSON conforming to Gate G10 schema."""
    evidence_path = tmp_path / "g10_schema_test.json"
    verifier = SoakVerifier(total_cycles=100, scan_rates_ms=[5.0, 10.0, 20.0, 50.0])

    res = verifier.run_soak(export_evidence=evidence_path)

    assert res.status == AgentStatus.SUCCESS
    assert evidence_path.is_file()

    payload = json.loads(evidence_path.read_text(encoding="utf-8"))

    # Top-level G10 schema conformance
    assert payload["gate"] == "G10"
    assert payload["work_package"] == "W029"
    assert payload["title"] == "Multi-Rate Closed-Loop Long-Term Soak & Stability Verification"
    assert payload["status"] == "success"
    assert payload["verdict"] == "success"
    assert payload["error_code"] is None
    assert payload["mode"] == "offline/mock"
    assert payload["classification"] == "TESTED_MOCK [offline/DEV only]"
    assert "timestamp_utc" in payload

    # Configuration section
    cfg = payload["configuration"]
    assert cfg["total_cycles"] == 100
    assert cfg["scan_rates_ms"] == [5.0, 10.0, 20.0, 50.0]
    assert cfg["max_heap_growth_threshold_kb"] == 100.0

    # Performance section
    perf = payload["performance"]
    assert "wall_duration_s" in perf
    assert "cycles_per_second" in perf
    assert perf["cycles_per_second"] > 0

    # Memory telemetry section
    mem = payload["memory_telemetry"]
    for k in [
        "tracemalloc_heap_growth_kb",
        "tracemalloc_peak_kb",
        "tracemalloc_current_kb",
        "psutil_rss_before_bytes",
        "psutil_rss_after_bytes",
        "psutil_rss_growth_kb",
        "psutil_vms_before_bytes",
        "psutil_vms_after_bytes",
        "zero_memory_leak_verified",
    ]:
        assert k in mem

    # Summary section
    summary = payload["summary"]
    assert summary["total_cycles_executed"] == 100
    assert summary["rates_tested_count"] == 4
    assert summary["all_rates_stable"] is True
    assert summary["total_nan_count"] == 0
    assert summary["total_divergence_count"] == 0
    assert summary["zero_nan_values_verified"] is True
    assert summary["zero_numerical_divergence_verified"] is True
    assert summary["zero_memory_leak_verified"] is True
    assert summary["zero_jitter_overflow_verified"] is True

    # Rate metrics with jitter fields
    for rate_key in ["5ms", "10ms", "20ms", "50ms"]:
        assert rate_key in payload["rate_metrics"]
        rm = payload["rate_metrics"][rate_key]
        assert rm["cycles_executed"] == 25
        assert rm["nan_count"] == 0
        assert rm["divergence_count"] == 0
        assert rm["jitter_overflow_count"] == 0
        assert rm["is_stable"] is True
        assert rm["min_cycle_time_ms"] > 0.0
        assert rm["max_cycle_time_ms"] >= rm["min_cycle_time_ms"]
        assert rm["mean_cycle_time_ms"] >= rm["min_cycle_time_ms"]
        assert rm["jitter_p99_ms"] >= 0.0

    # Invariants verified section
    invariants = payload["invariants_verified"]
    assert invariants["multi_rate_stability"] is True
    assert invariants["bounded_level_tracking_le_1pct"] is True
    assert invariants["zero_memory_leak_lt_100kb"] is True
    assert invariants["zero_nan_values"] is True
    assert invariants["zero_numerical_divergence"] is True
    assert invariants["zero_jitter_overflow"] is True
    assert invariants["fail_safe_actuator_bounds"] is True
    assert invariants["hardware_lockout_active"] is True

