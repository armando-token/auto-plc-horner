"""Single GUI Agent Boundary Controller for Cscape 10.2 on winsta0\\Default.

Enforces exclusive HWND ownership via file-backed inter-process lock, preventing
multi-agent desktop contention, focus corruption, and race conditions. Fails closed
if Cscape is closed, minimized, obscured, or contention is detected.
"""

from contextlib import contextmanager
import ctypes
import os
import time
from typing import Any, Dict, Generator, Optional
import win32con
import win32gui
from pydantic import BaseModel, Field

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.automation.lifecycle import CscapeLifecycleController

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32


class LockStatus(BaseModel):
    """Current state of the GUI boundary lock."""
    is_locked: bool
    owner_pid: Optional[int] = None
    lock_file: str
    acquired_at_utc: Optional[str] = None
    target_hwnd: Optional[int] = None


class GUIBoundaryController:
    """Exclusive controller guarding Cscape interactive GUI access on winsta0\\Default."""

    DEFAULT_LOCK_PATH = r"work\disposable\cscape_gui.lock"

    def __init__(self, lock_path: Optional[str] = None):
        self.project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        rel_lock = lock_path or self.DEFAULT_LOCK_PATH
        self.lock_path = os.path.join(self.project_root, rel_lock)
        self._lock_file_handle: Optional[int] = None

    def is_locked(self) -> bool:
        """Check if lock file exists and is held."""
        return self.get_lock_status().is_locked

    def get_lock_status(self) -> LockStatus:
        """Get structured status of GUI boundary lock."""
        if not os.path.exists(self.lock_path):
            return LockStatus(is_locked=False, lock_file=self.lock_path)
        try:
            with open(self.lock_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content:
                parts = content.split(":")
                pid = int(parts[0])
                ts = parts[1] if len(parts) > 1 else None
                import psutil
                if psutil.pid_exists(pid):
                    return LockStatus(
                        is_locked=True,
                        owner_pid=pid,
                        lock_file=self.lock_path,
                        acquired_at_utc=ts,
                    )
        except Exception:
            return LockStatus(is_locked=True, lock_file=self.lock_path)
        return LockStatus(is_locked=False, lock_file=self.lock_path)

    def acquire_lock(self, timeout: float = 5.0) -> ExecutionResult:
        """Acquire exclusive single-agent GUI lock."""
        start_time = time.time()
        os.makedirs(os.path.dirname(self.lock_path), exist_ok=True)

        current_pid = os.getpid()

        while time.time() - start_time < timeout:
            try:
                # O_CREAT | O_EXCL provides atomic creation on POSIX and Windows
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                payload = f"{current_pid}:{time.time()}".encode("utf-8")
                os.write(fd, payload)
                os.close(fd)
                return ExecutionResult.success(
                    details=f"Acquired exclusive GUI lock for PID {current_pid}.",
                    data={"pid": current_pid, "lock_file": self.lock_path}
                )
            except FileExistsError:
                # Check stale lock
                try:
                    with open(self.lock_path, "r", encoding="utf-8") as f:
                        content = f.read().strip()
                    if content:
                        owner_pid = int(content.split(":")[0])
                        import psutil
                        if not psutil.pid_exists(owner_pid):
                            # Stale lock: remove and retry
                            os.remove(self.lock_path)
                            continue
                except Exception:
                    pass
                time.sleep(0.2)

        return ExecutionResult.blocked(
            error_code="GUI_CONTENTION_BLOCKED",
            details=f"Failed to acquire GUI lock within {timeout}s: another agent holds winsta0\\Default exclusive access.",
            data={"lock_file": self.lock_path}
        )

    def release_lock(self) -> ExecutionResult:
        """Release the GUI boundary lock."""
        if os.path.exists(self.lock_path):
            try:
                os.remove(self.lock_path)
                return ExecutionResult.success(
                    details="Released GUI boundary lock cleanly.",
                    data={"lock_file": self.lock_path}
                )
            except Exception as e:
                return ExecutionResult.failed(
                    error_code="LOCK_RELEASE_ERROR",
                    details=f"Error removing lock file '{self.lock_path}': {e}",
                )
        return ExecutionResult.success(details="Lock was not held.")

    @contextmanager
    def guard_gui(self, timeout: float = 5.0) -> Generator[Dict[str, Any], None, None]:
        """Context manager enforcing single-agent lock during GUI automation."""
        acquire_res = self.acquire_lock(timeout=timeout)
        if acquire_res.status != AgentStatus.SUCCESS:
            raise PermissionError(f"GUI_CONTENTION: {acquire_res.details}")

        try:
            yield acquire_res.data
        finally:
            self.release_lock()

    @classmethod
    def assert_cscape_active_and_visible(cls) -> ExecutionResult:
        """Verify Cscape main window is running, visible, and not minimized on winsta0\\Default."""
        ctrl = CscapeLifecycleController()
        procs = ctrl.find_cscape_processes()
        if not procs:
            return ExecutionResult.failed(
                error_code="CSCAPE_NOT_RUNNING",
                details="FAIL_CLOSED: No Cscape.exe process is running on the system.",
            )

        main_win = ctrl.find_main_window()
        if not main_win:
            return ExecutionResult.failed(
                error_code="CSCAPE_WINDOW_NOT_FOUND",
                details="FAIL_CLOSED: Cscape process running, but main window handle could not be resolved.",
            )

        hwnd = main_win["hwnd"]
        if win32gui.IsIconic(hwnd):
            return ExecutionResult.blocked(
                error_code="CSCAPE_WINDOW_MINIMIZED",
                details=f"FAIL_CLOSED: Cscape window (HWND {hex(hwnd)}) is minimized.",
            )

        if not main_win["is_visible"]:
            return ExecutionResult.blocked(
                error_code="CSCAPE_WINDOW_HIDDEN",
                details=f"FAIL_CLOSED: Cscape window (HWND {hex(hwnd)}) is hidden or obscured.",
            )

        return ExecutionResult.success(
            details=f"Cscape verified active, visible, and unminimized (PID {main_win['pid']}, HWND {main_win['hwnd_hex']}).",
            data=main_win,
        )
