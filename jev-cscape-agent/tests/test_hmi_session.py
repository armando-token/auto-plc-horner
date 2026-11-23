"""Tests for HMI Navigation Session & Multi-Screen SVG Visualizer (Gate G9, W043)."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.navigation import (
    HMINavigationGraph,
    SecurityAccessDeniedError,
    SecurityLevel,
)
from jev_cscape.hmi.session import HmiNavigationSession, NavigationEventRecord
from scripts.run_hmi_navigation_session import run_hmi_navigation_session


def test_session_initialization() -> None:
    """Verify HmiNavigationSession initializes with default screen 1 and breadcrumbs."""
    session = HmiNavigationSession()
    assert session.current_screen_id == 1
    assert session.current_screen.name == "Main Overview"
    assert session.breadcrumb_trail == [1]
    assert len(session.event_log) == 0


def test_rbac_security_blocking() -> None:
    """Verify unauthorized role cannot transition to protected screens."""
    session = HmiNavigationSession(default_role=SecurityLevel.VIEWER)

    # Attempt to open Recipe screen (Screen 6, requires SUPERVISOR) as VIEWER
    res = session.navigate_to(6)
    assert res.status == AgentStatus.BLOCKED
    assert res.error_code == "SECURITY_ACCESS_DENIED"
    assert session.current_screen_id == 1  # Screen did not change
    assert len(session.event_log) == 1
    assert session.event_log[0].status == "DENIED"

    # Attempt to open Diagnostics (Screen 7, requires ENGINEER) as OPERATOR
    session.set_user_role(SecurityLevel.OPERATOR)
    res_diag = session.navigate_to(7)
    assert res_diag.status == AgentStatus.BLOCKED
    assert res_diag.error_code == "SECURITY_ACCESS_DENIED"
    assert session.current_screen_id == 1


def test_breadcrumb_trail_and_unwind() -> None:
    """Verify breadcrumb stack pushes and pops accurately across navigation steps."""
    session = HmiNavigationSession(default_role=SecurityLevel.OPERATOR)

    # 1 -> 2 (Tank 1)
    res = session.navigate_to(2)
    assert res.status == AgentStatus.SUCCESS
    assert session.current_screen_id == 2
    assert session.breadcrumb_trail == [1, 2]

    # 2 -> 3 (Tank 2)
    res = session.navigate_to(3)
    assert res.status == AgentStatus.SUCCESS
    assert session.current_screen_id == 3
    assert session.breadcrumb_trail == [1, 2, 3]

    # Navigate Back: 3 -> 2
    res_back = session.navigate_back()
    assert res_back.status == AgentStatus.SUCCESS
    assert session.current_screen_id == 2
    assert session.breadcrumb_trail == [1, 2]

    # Navigate Back: 2 -> 1
    res_back2 = session.navigate_back()
    assert res_back2.status == AgentStatus.SUCCESS
    assert session.current_screen_id == 1
    assert session.breadcrumb_trail == [1]

    # Reset to home on already home
    res_home = session.reset_to_home()
    assert res_home.status == AgentStatus.SUCCESS
    assert session.current_screen_id == 1
    assert session.breadcrumb_trail == [1]


def test_screen_not_found_handling() -> None:
    """Verify navigating to nonexistent screen ID returns failed status."""
    session = HmiNavigationSession()
    res = session.navigate_to(9999)
    assert res.status == AgentStatus.FAILED
    assert res.error_code == "SCREEN_NOT_FOUND"


def test_svg_rendering_across_screens(tmp_path: Path) -> None:
    """Verify session can render multiple SVG screens to disk."""
    session = HmiNavigationSession()

    svg1 = session.render_screen_svg(screen_id=1, output_file=tmp_path / "screen1.svg")
    assert "<svg" in svg1
    assert "</svg>" in svg1
    assert (tmp_path / "screen1.svg").exists()

    svg5 = session.render_screen_svg(screen_id=5, output_file=tmp_path / "screen5.svg")
    assert "<svg" in svg5
    assert "</svg>" in svg5
    assert (tmp_path / "screen5.svg").exists()

    svg6 = session.render_screen_svg(screen_id=6, output_file=tmp_path / "screen6.svg")
    assert "<svg" in svg6
    assert "</svg>" in svg6
    assert (tmp_path / "screen6.svg").exists()


def test_export_session_evidence(tmp_path: Path) -> None:
    """Verify session evidence exports valid JSON with complete event log."""
    session = HmiNavigationSession(default_role=SecurityLevel.OPERATOR)
    session.navigate_to(2)
    session.navigate_back()

    out_file = tmp_path / "evidence.json"
    evidence = session.export_session_evidence(output_file=out_file)

    assert out_file.exists()
    assert evidence["session_summary"]["total_events"] == 2
    assert evidence["topology_verification"]["is_fully_reachable"] is True
    assert len(evidence["event_trail"]) == 2


def test_run_hmi_navigation_session_script(tmp_path: Path) -> None:
    """Verify the canonical script runner executes without errors."""
    res = run_hmi_navigation_session(repo_root=tmp_path)
    assert res.status == AgentStatus.SUCCESS
    assert res.data["total_events"] >= 8
    assert res.data["denied_security_attempts"] >= 2
    assert Path(res.data["evidence_path"]).exists()
