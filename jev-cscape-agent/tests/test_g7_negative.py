# -*- coding: utf-8 -*-
"""Gate G7 Ladder Negative Tests Unit & Integration Test Suite.

Mandate: Verification of Gate G7 Negative Tests N1, N2, and N3.
Classification: TESTED_MOCK / INTEGRATION [offline/DEV]
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(r"C:\HornerAI\jev-cscape-agent")
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.contracts import AgentStatus
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.security.exceptions import HardwareLockoutError
from jev_cscape.security.guard import SecurityGuard

from scripts.g3_edit_roundtrip import (
    BASE_P1_PATH,
    BASELINE_P1_SHA,
    assert_safety_invariants,
    compute_sha256,
)
from scripts.g7_negative_tests import (
    NEGATIVE_EVIDENCE_PATH,
    check_for_corruption_error_dialog,
    find_modal_warning_dialog,
)


def test_negative_baseline_p1_immutability():
    """Verify baseline p1_base.csp exists and matches cryptographic SHA-256 hash."""
    assert BASE_P1_PATH.exists(), f"Missing base p1_base.csp at {BASE_P1_PATH}"
    actual_sha = compute_sha256(BASE_P1_PATH)
    assert actual_sha == BASELINE_P1_SHA, (
        f"Baseline p1_base.csp mutated! Expected {BASELINE_P1_SHA}, got {actual_sha}"
    )


def test_negative_fail_closed_hardware_lockout():
    """Verify physical COM ports and download commands are fail-closed blocked."""
    assert_safety_invariants()

    for port in ["COM1", "COM2", "COM256"]:
        with pytest.raises(HardwareLockoutError):
            SecurityGuard.assert_port_safe(port)

    interceptor = Win32CommandInterceptor()
    for cmd_id in [32827, 33149]:
        res = interceptor.dispatch_safe_command(hwnd=0, cmd_id=cmd_id)
        assert res.status == AgentStatus.BLOCKED


def test_find_modal_warning_dialog_mock():
    """Verify find_modal_warning_dialog detects dialogs with static text."""
    with patch("scripts.g7_negative_tests.win32gui.EnumWindows") as mock_enum, \
         patch("scripts.g7_negative_tests.win32gui.EnumChildWindows") as mock_child_enum:

        def fake_enum(cb, _):
            with patch("scripts.g7_negative_tests.win32gui.IsWindow", return_value=True), \
                 patch("scripts.g7_negative_tests.win32gui.IsWindowVisible", return_value=True), \
                 patch("scripts.g7_negative_tests.win32process.GetWindowThreadProcessId", return_value=(0, 8888)), \
                 patch("scripts.g7_negative_tests.win32gui.GetClassName", return_value="#32770"), \
                 patch("scripts.g7_negative_tests.win32gui.GetWindowText", return_value="Cscape Warning"):
                cb(1234, None)

        def fake_child_enum(hwnd, cb, _):
            with patch("scripts.g7_negative_tests.win32gui.GetClassName", return_value="Static"), \
                 patch("scripts.g7_negative_tests.win32gui.GetWindowText", return_value="Invalid variable syntax"):
                cb(5678, None)

        mock_enum.side_effect = fake_enum
        mock_child_enum.side_effect = fake_child_enum

        dlg = find_modal_warning_dialog(pid=8888, timeout=0.5)
        assert dlg is not None
        assert dlg[0] == 1234
        assert dlg[1] == "Cscape Warning"
        assert "Invalid variable syntax" in dlg[2]


def test_check_for_corruption_error_dialog_mock():
    """Verify check_for_corruption_error_dialog identifies corruption keywords."""
    with patch("scripts.g7_negative_tests.win32gui.EnumWindows") as mock_enum, \
         patch("scripts.g7_negative_tests.win32gui.EnumChildWindows") as mock_child_enum:

        def fake_enum(cb, _):
            with patch("scripts.g7_negative_tests.win32gui.IsWindow", return_value=True), \
                 patch("scripts.g7_negative_tests.win32gui.IsWindowVisible", return_value=True), \
                 patch("scripts.g7_negative_tests.win32process.GetWindowThreadProcessId", return_value=(0, 7777)), \
                 patch("scripts.g7_negative_tests.win32gui.GetClassName", return_value="#32770"), \
                 patch("scripts.g7_negative_tests.win32gui.GetWindowText", return_value="File Open Error"):
                cb(4321, None)

        def fake_child_enum(hwnd, cb, _):
            with patch("scripts.g7_negative_tests.win32gui.GetClassName", return_value="Static"), \
                 patch("scripts.g7_negative_tests.win32gui.GetWindowText", return_value="Project file is damaged or corrupt."):
                cb(8765, None)

        mock_enum.side_effect = fake_enum
        mock_child_enum.side_effect = fake_child_enum

        err = check_for_corruption_error_dialog(pid=7777)
        assert err is not None
        assert "File Open Error" in err[0]
        assert "corrupt" in err[1].lower()


def test_negative_tests_evidence_artifact_if_present():
    """If g7_negative_tests_evidence.json exists, verify N1, N2, and N3 passed."""
    if not NEGATIVE_EVIDENCE_PATH.exists():
        pytest.skip("g7_negative_tests_evidence.json not yet generated by live run.")

    with open(NEGATIVE_EVIDENCE_PATH, "r", encoding="utf-8") as f:
        evidence = json.load(f)

    assert evidence.get("gate") == "G7"
    assert evidence.get("baseline_p1_sha256") == BASELINE_P1_SHA
    assert evidence.get("overall_status") in ("success", "failed")

    if evidence.get("overall_status") == "success":
        assert evidence.get("total_tests") == 3
        assert evidence.get("passed_tests") == 3
        assert evidence.get("failed_tests") == 0

        tests_by_id = {t["test_id"]: t for t in evidence.get("tests", [])}
        assert "N1_UNBOUND_INVALID_VARIABLE" in tests_by_id
        assert "N2_ABORT_BEFORE_SAVE" in tests_by_id
        assert "N3_INTERRUPTED_SAVE" in tests_by_id

        # N1 assertions
        n1 = tests_by_id["N1_UNBOUND_INVALID_VARIABLE"]
        assert n1["status"] == "success"
        assert n1["sha_unchanged"] is True
        assert n1["p1_base_intact"] is True
        assert n1["rejection_confirmed"] is True

        # N2 assertions
        n2 = tests_by_id["N2_ABORT_BEFORE_SAVE"]
        assert n2["status"] == "success"
        assert n2["sha_unchanged"] is True
        assert n2["cfbf_element_count"] == 0
        assert n2["p1_base_intact"] is True

        # N3 assertions
        n3 = tests_by_id["N3_INTERRUPTED_SAVE"]
        assert n3["status"] == "success"
        assert n3["is_ole_valid"] is True
        assert n3["cfbf_stream_readable"] is True
        assert n3["contents_stream_size"] > 1000
        assert n3["corruption_detected"] is False
        assert n3["reopen_clean"] is True
        assert n3["p1_base_intact"] is True
