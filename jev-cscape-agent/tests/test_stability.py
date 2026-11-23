"""Tests for StabilityGuardian process monitoring and retry mechanics."""

import os
import pytest
from jev_cscape.automation.stability import (
    StabilityGuardian,
    ProcessHealthSnapshot,
    StabilityBenchmark,
)
from jev_cscape.contracts import AgentStatus


def test_snapshot_current_process():
    guardian = StabilityGuardian()
    snap = guardian.get_snapshot(pid=os.getpid())
    assert snap.is_running is True
    assert snap.is_hung is False
    assert snap.memory_rss_mb > 0
    assert snap.num_threads >= 1


def test_snapshot_nonexistent_process():
    guardian = StabilityGuardian()
    snap = guardian.get_snapshot(pid=9999999)
    assert snap.is_running is False
    assert snap.memory_rss_bytes == 0


def test_retry_with_backoff_success():
    counter = {"attempts": 0}

    def flaky():
        counter["attempts"] += 1
        if counter["attempts"] < 2:
            raise ValueError("Temporary failure")
        return "success"

    res = StabilityGuardian.retry_with_backoff(flaky, max_attempts=3, initial_delay=0.01)
    assert res == "success"
    assert counter["attempts"] == 2


def test_retry_with_backoff_exceeds_max():
    def fail():
        raise RuntimeError("Persistent error")

    with pytest.raises(RuntimeError, match="Persistent error"):
        StabilityGuardian.retry_with_backoff(fail, max_attempts=2, initial_delay=0.01)


def test_run_benchmark_current_process():
    guardian = StabilityGuardian()
    bench = guardian.run_benchmark(pid=os.getpid(), duration_seconds=0.3, sample_interval=0.1)
    assert bench.status == AgentStatus.SUCCESS
    assert bench.samples_count >= 2
    assert bench.hung_detected is False
    assert bench.peak_memory_mb > 0
