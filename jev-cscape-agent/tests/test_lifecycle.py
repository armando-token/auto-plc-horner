"""Tests for CscapeLifecycleController non-destructive window queries and safety."""

import pytest
from jev_cscape.automation.lifecycle import CscapeLifecycleController
from jev_cscape.contracts import AgentStatus


def test_lifecycle_controller_initialization():
    ctrl = CscapeLifecycleController()
    assert "Cscape.exe" in ctrl.cscape_exe


def test_inspect_when_cscape_not_running():
    # If Cscape is not running, inspect() must return failed with CSCAPE_NOT_RUNNING (fail-closed)
    ctrl = CscapeLifecycleController()
    procs = ctrl.find_cscape_processes()
    if not procs:
        res = ctrl.inspect()
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "CSCAPE_NOT_RUNNING"
