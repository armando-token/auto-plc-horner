"""Stability and Health Guardian for Cscape 10.2 Automation.

Monitors process responsiveness, detects hung windows via Win32 IsHungAppWindow,
tracks memory/resource usage, and provides retry-with-backoff mechanics for UI stability.
"""

import ctypes
import os
import time
from typing import Any, Callable, Dict, List, Optional, TypeVar
import psutil
from pydantic import BaseModel, Field

from jev_cscape.contracts import ExecutionResult, AgentStatus

user32 = ctypes.windll.user32
T = TypeVar("T")


class ProcessHealthSnapshot(BaseModel):
    """Snapshot of process resource consumption and responsiveness."""
    pid: int
    is_running: bool
    is_hung: bool
    memory_rss_bytes: int
    memory_rss_mb: float
    cpu_percent: float
    num_threads: int
    timestamp_utc: float


class StabilityBenchmark(BaseModel):
    """Result of stability evaluation over a test interval."""
    status: AgentStatus
    samples_count: int
    avg_memory_mb: float
    peak_memory_mb: float
    hung_detected: bool
    details: str
    snapshots: List[ProcessHealthSnapshot] = Field(default_factory=list)


class StabilityGuardian:
    """Monitors stability of Cscape host process without UI interruption."""

    MAX_SAFE_MEMORY_MB = 1024.0  # Cscape is 32-bit x86; alert if approaching 1GB

    def __init__(self, pid: Optional[int] = None):
        self.pid = pid

    @staticmethod
    def is_window_hung(hwnd: int) -> bool:
        """Check if target window is hung using Win32 IsHungAppWindow."""
        try:
            return bool(user32.IsHungAppWindow(hwnd))
        except Exception:
            return False

    def get_snapshot(self, pid: Optional[int] = None, hwnd: Optional[int] = None) -> ProcessHealthSnapshot:
        """Capture health snapshot for target process."""
        target_pid = pid or self.pid
        now = time.time()

        if not target_pid or not psutil.pid_exists(target_pid):
            return ProcessHealthSnapshot(
                pid=target_pid or 0,
                is_running=False,
                is_hung=False,
                memory_rss_bytes=0,
                memory_rss_mb=0.0,
                cpu_percent=0.0,
                num_threads=0,
                timestamp_utc=now,
            )

        try:
            proc = psutil.Process(target_pid)
            mem = proc.memory_info().rss
            cpu = proc.cpu_percent(interval=0.05)
            threads = proc.num_threads()
            hung = self.is_window_hung(hwnd) if hwnd else False

            return ProcessHealthSnapshot(
                pid=target_pid,
                is_running=True,
                is_hung=hung,
                memory_rss_bytes=mem,
                memory_rss_mb=round(mem / (1024 * 1024), 2),
                cpu_percent=round(cpu, 1),
                num_threads=threads,
                timestamp_utc=now,
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return ProcessHealthSnapshot(
                pid=target_pid,
                is_running=False,
                is_hung=False,
                memory_rss_bytes=0,
                memory_rss_mb=0.0,
                cpu_percent=0.0,
                num_threads=0,
                timestamp_utc=now,
            )

    @classmethod
    def retry_with_backoff(
        cls,
        operation: Callable[[], T],
        max_attempts: int = 3,
        initial_delay: float = 0.2,
        backoff_factor: float = 2.0,
    ) -> T:
        """Execute a UI automation operation with exponential backoff on failure."""
        delay = initial_delay
        last_exception = None

        for attempt in range(1, max_attempts + 1):
            try:
                return operation()
            except Exception as e:
                last_exception = e
                if attempt == max_attempts:
                    break
                time.sleep(delay)
                delay *= backoff_factor

        raise last_exception or RuntimeError("Operation failed after max attempts.")

    def run_benchmark(
        self,
        pid: int,
        duration_seconds: float = 1.0,
        sample_interval: float = 0.2,
        hwnd: Optional[int] = None,
    ) -> StabilityBenchmark:
        """Evaluate process health across an interval and return benchmark."""
        snapshots: List[ProcessHealthSnapshot] = []
        start_time = time.time()

        while time.time() - start_time < duration_seconds:
            snap = self.get_snapshot(pid=pid, hwnd=hwnd)
            snapshots.append(snap)
            if not snap.is_running:
                break
            time.sleep(sample_interval)

        if not snapshots:
            return StabilityBenchmark(
                status=AgentStatus.INCONCLUSIVE,
                samples_count=0,
                avg_memory_mb=0.0,
                peak_memory_mb=0.0,
                hung_detected=False,
                details="No snapshots collected.",
            )

        running_snaps = [s for s in snapshots if s.is_running]
        if not running_snaps:
            return StabilityBenchmark(
                status=AgentStatus.FAILED,
                samples_count=len(snapshots),
                avg_memory_mb=0.0,
                peak_memory_mb=0.0,
                hung_detected=False,
                details=f"Process PID {pid} is not running or terminated prematurely.",
                snapshots=snapshots,
            )

        mems = [s.memory_rss_mb for s in running_snaps]
        avg_mem = round(sum(mems) / len(mems), 2)
        peak_mem = max(mems)
        any_hung = any(s.is_hung for s in running_snaps)

        status = AgentStatus.SUCCESS
        details = f"Session stable over {duration_seconds}s interval: avg memory {avg_mem}MB, peak {peak_mem}MB."
        if any_hung:
            status = AgentStatus.FAILED
            details = f"Process hung window detected during stability monitoring."
        elif peak_mem > self.MAX_SAFE_MEMORY_MB:
            status = AgentStatus.PARTIAL
            details = f"Memory usage warning: peak {peak_mem}MB exceeds safe 32-bit threshold."

        return StabilityBenchmark(
            status=status,
            samples_count=len(snapshots),
            avg_memory_mb=avg_mem,
            peak_memory_mb=peak_mem,
            hung_detected=any_hung,
            details=details,
            snapshots=snapshots,
        )
