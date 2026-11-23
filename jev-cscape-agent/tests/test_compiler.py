"""Tests for CscapeCompilerDispatcher error check compilation and safety."""

import pytest
from jev_cscape.automation.compiler import CscapeCompilerDispatcher, CompilationResult
from jev_cscape.automation.gui_controller import GUIBoundaryController
from jev_cscape.contracts import AgentStatus


def test_compiler_dispatcher_initialization():
    disp = CscapeCompilerDispatcher()
    assert disp.ERROR_CHECK_CMD_ID == 32826


def test_compiler_offline_mock_compilation():
    disp = CscapeCompilerDispatcher()
    mock_data = {
        "success": True,
        "errors_count": 0,
        "warnings_count": 0,
        "command_id": 32826,
        "mode": "offline/mock",
        "compilation_time_seconds": 0.42,
        "details": "Mock clean compile verified with 0 errors, 0 warnings.",
    }
    res = disp.trigger_error_check(mock_result=mock_data)

    assert res.status == AgentStatus.SUCCESS
    assert res.data["mode"] == "offline/mock"
    comp = res.data["compilation"]
    assert comp["success"] is True
    assert comp["errors_count"] == 0
    assert comp["warnings_count"] == 0
    assert comp["command_id"] == 32826


def test_compiler_fail_closed_when_cscape_not_running(monkeypatch):
    from jev_cscape.automation.lifecycle import CscapeLifecycleController
    disp = CscapeCompilerDispatcher()
    monkeypatch.setattr(CscapeLifecycleController, "find_cscape_processes", lambda self: [])

    res = disp.trigger_error_check()
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "CSCAPE_NOT_RUNNING"


def test_compiler_contention_blocked(tmp_path):
    lock_file = str(tmp_path / "compiler_contention.lock")
    gui_ctrl = GUIBoundaryController(lock_path=lock_file)
    disp = CscapeCompilerDispatcher(gui_controller=gui_ctrl)

    # Acquire lock in another controller first
    holder = GUIBoundaryController(lock_path=lock_file)
    acq_res = holder.acquire_lock()
    assert acq_res.status == AgentStatus.SUCCESS

    # Dispatching error check must fail closed with BLOCKED
    res = disp.trigger_error_check()
    assert res.status == AgentStatus.BLOCKED
    assert res.error_code == "GUI_CONTENTION_BLOCKED"

    # Cleanup
    holder.release_lock()
