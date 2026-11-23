"""Tests for JEV Cscape Agent 4-State Contract Specification."""

import json
import pytest
from jev_cscape.contracts import AgentStatus, ExecutionResult


def test_agent_status_values():
    assert AgentStatus.SUCCESS.value == "success"
    assert AgentStatus.PARTIAL.value == "partial"
    assert AgentStatus.FAILED.value == "failed"
    assert AgentStatus.BLOCKED.value == "blocked"
    assert AgentStatus.INCONCLUSIVE.value == "inconclusive"
    assert len(AgentStatus) == 5


def test_execution_result_success():
    res = ExecutionResult.success(details="All checks passed.", data={"val": 123})
    assert res.status == AgentStatus.SUCCESS
    assert res.error_code is None
    assert res.details == "All checks passed."
    assert res.data["val"] == 123

    dump = json.loads(res.model_dump_json())
    assert dump["status"] == "success"
    assert dump["error_code"] is None
    assert dump["details"] == "All checks passed."


def test_execution_result_partial():
    res = ExecutionResult.partial(
        details="Project opened with 2 uninitialized graphical symbols.",
        data={"uninitialized_count": 2}
    )
    assert res.status == AgentStatus.PARTIAL
    assert res.error_code is None
    assert res.data["uninitialized_count"] == 2


def test_execution_result_failed():
    res = ExecutionResult.failed(
        error_code="SYNTAX_ERROR",
        details="ST compilation failed at line 12.",
        data={"line": 12}
    )
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "SYNTAX_ERROR"
    assert res.data["line"] == 12


def test_execution_result_blocked():
    res = ExecutionResult.blocked(
        error_code="FAIL_CLOSED_HARDWARE_LOCKOUT",
        details="Access to COM3 prohibited."
    )
    assert res.status == AgentStatus.BLOCKED
    assert res.error_code == "FAIL_CLOSED_HARDWARE_LOCKOUT"


def test_execution_result_inconclusive():
    res = ExecutionResult.inconclusive(
        details="Preconditions unverified."
    )
    assert res.status == AgentStatus.INCONCLUSIVE
    assert res.error_code is None
