"""Tests for NavigationMap Cscape topology and command safety."""

import pytest
from jev_cscape.automation.navigation_map import (
    NavigationMap,
    CommandSafety,
    NavCommand,
)


def test_error_check_command_present_and_safe():
    cmd = NavigationMap.get_command_by_id(32826)
    assert cmd is not None
    assert cmd.name == "ID_PROGRAM_ERRORCHECK"
    assert cmd.safety == CommandSafety.SAFE
    assert cmd.accelerator == "Ctrl+F7"


def test_download_commands_blocked():
    blocked = NavigationMap.get_blocked_commands()
    blocked_ids = {c.id for c in blocked}
    assert 32827 in blocked_ids  # ID_PROGRAM_DOWNLOAD
    assert 33149 in blocked_ids  # ID_CONTROLLER_DOWNLOAD
    for c in blocked:
        assert c.safety == CommandSafety.BLOCKED


def test_panes_defined():
    pane_names = [p.name for p in NavigationMap.PANES]
    assert "Project Navigator" in pane_names
    assert "Compiler Output Pane" in pane_names
    assert "MDI Logic Workspace" in pane_names


def test_export_topology():
    top = NavigationMap.export_topology()
    assert top["version"] == "10.2.751.4"
    assert len(top["commands"]) > 10
    assert 32827 in top["blocked_command_ids"]
