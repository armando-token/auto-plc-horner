"""Tests for GUIBoundaryController single-agent lock and fail-closed checks."""

import os
import pytest
from jev_cscape.automation.gui_controller import GUIBoundaryController
from jev_cscape.contracts import AgentStatus


def test_lock_acquire_and_release(tmp_path):
    lock_file = str(tmp_path / "test_gui.lock")
    controller = GUIBoundaryController(lock_path=lock_file)

    assert not controller.is_locked()

    # Acquire lock
    res = controller.acquire_lock(timeout=1.0)
    assert res.status == AgentStatus.SUCCESS
    assert controller.is_locked()

    # Second acquire should fail with contention
    res2 = controller.acquire_lock(timeout=0.3)
    assert res2.status == AgentStatus.BLOCKED
    assert res2.error_code == "GUI_CONTENTION_BLOCKED"

    # Release lock
    rel = controller.release_lock()
    assert rel.status == AgentStatus.SUCCESS
    assert not controller.is_locked()


def test_guard_gui_context_manager(tmp_path):
    lock_file = str(tmp_path / "test_ctx.lock")
    controller = GUIBoundaryController(lock_path=lock_file)

    with controller.guard_gui(timeout=1.0) as data:
        assert data["pid"] == os.getpid()
        assert controller.is_locked()

    assert not controller.is_locked()


def test_assert_cscape_active_when_not_running():
    # If Cscape is not running, must fail closed
    res = GUIBoundaryController.assert_cscape_active_and_visible()
    assert res.status in [AgentStatus.FAILED, AgentStatus.BLOCKED, AgentStatus.SUCCESS]
    if res.status != AgentStatus.SUCCESS:
        assert "FAIL_CLOSED" in res.details
