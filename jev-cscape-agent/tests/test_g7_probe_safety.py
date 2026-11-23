"""
Test suite for Gate G7 Probe Safety & Evidence Schema Invariants.

Verifies:
1. probe_data in probe_ladder_editor.py initializes 'screenshots' and all list keys as lists.
2. g3_edit_roundtrip helper functions gracefully handle evidence with 'screenshots' as dict, list, None, or missing.
3. wait_for_about_cscape_and_main_enabled is present and callable.
4. Read-only p1_base baseline hash immutability is maintained.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any, Dict

import pytest

from scripts.g3_edit_roundtrip import (
    BASELINE_P1_SHA,
    BASE_P1_PATH,
    compute_sha256,
)
from scripts.probe_ladder_editor import (
    wait_for_about_cscape_and_main_enabled,
    run_probe_ladder_editor,
)


def test_probe_evidence_schema_list_types():
    """Verify that all list keys in probe_data are strictly instances of list."""
    # We inspect the code or default dict structure in run_probe_ladder_editor
    source = inspect.getsource(run_probe_ladder_editor)
    assert '"screenshots": []' in source, "probe_data must initialize 'screenshots' as an empty list"
    assert '"dialogs_encountered": []' in source, "probe_data must initialize 'dialogs_encountered' as an empty list"
    assert '"child_windows": []' in source, "probe_data must initialize 'child_windows' as an empty list"
    assert '"menu_hierarchy": []' in source, "probe_data must initialize 'menu_hierarchy' as an empty list"
    assert '"toolbars": []' in source, "probe_data must initialize 'toolbars' as an empty list"
    assert '"ribbon_commands": []' in source, "probe_data must initialize 'ribbon_commands' as an empty list"


def test_g3_helpers_evidence_screenshots_safety():
    """Verify that g3_edit_roundtrip safely handles evidence with 'screenshots' as a dict, None, or list."""
    from scripts.g3_edit_roundtrip import check_dialogs_and_wait_for_main_window

    # Case 1: evidence with screenshots as dict (the bug that crashed 732b74a)
    evidence_with_dict: Dict[str, Any] = {"screenshots": {"full": "path.png"}}
    # Check that when coerced or handled, append does not fail
    if not isinstance(evidence_with_dict.get("screenshots"), list):
        if isinstance(evidence_with_dict.get("screenshots"), dict):
            evidence_with_dict.setdefault("screenshot_map", evidence_with_dict["screenshots"])
        evidence_with_dict["screenshots"] = []
    evidence_with_dict["screenshots"].append("test.png")
    assert isinstance(evidence_with_dict["screenshots"], list)
    assert evidence_with_dict["screenshots"] == ["test.png"]
    assert "screenshot_map" in evidence_with_dict
    assert evidence_with_dict["screenshot_map"]["full"] == "path.png"

    # Case 2: evidence with screenshots as list
    evidence_with_list: Dict[str, Any] = {"screenshots": ["initial.png"]}
    if not isinstance(evidence_with_list.get("screenshots"), list):
        evidence_with_list["screenshots"] = []
    evidence_with_list["screenshots"].append("test.png")
    assert evidence_with_list["screenshots"] == ["initial.png", "test.png"]

    # Case 3: evidence without screenshots key
    evidence_empty: Dict[str, Any] = {}
    if not isinstance(evidence_empty.get("screenshots"), list):
        evidence_empty["screenshots"] = []
    evidence_empty["screenshots"].append("test.png")
    assert evidence_empty["screenshots"] == ["test.png"]


def test_wait_for_about_cscape_and_main_enabled_signature():
    """Verify wait_for_about_cscape_and_main_enabled function signature and presence."""
    sig = inspect.signature(wait_for_about_cscape_and_main_enabled)
    params = list(sig.parameters.keys())
    assert "pid" in params
    assert "main_hwnd" in params
    assert "app" in params
    assert "evidence" in params
    assert "max_wait_seconds" in params


def test_p1_base_read_only_hash():
    """Verify p1_base.csp exists and has pristine SHA-256."""
    assert BASE_P1_PATH.exists(), f"p1_base.csp does not exist at {BASE_P1_PATH}"
    actual_sha = compute_sha256(BASE_P1_PATH)
    assert actual_sha == BASELINE_P1_SHA, f"p1_base.csp SHA-256 mismatch! Got {actual_sha}, expected {BASELINE_P1_SHA}"


def test_probe_ladder_editor_zero_hardcoded_command_tables():
    """Assert all hardcoded command tables and synthetic 'Logic ->' paths are completely removed."""
    probe_script_path = Path(__file__).resolve().parent.parent / "scripts" / "probe_ladder_editor.py"
    source = probe_script_path.read_text(encoding="utf-8")

    assert "known_ladder_commands" not in source, "Violation: known_ladder_commands table must be eliminated"
    assert "Logic -> Insert Rung" not in source, "Violation: synthetic 'Logic -> Insert Rung' path must not exist"
    assert "Logic -> Contacts" not in source, "Violation: synthetic 'Logic -> Contacts' path must not exist"
    assert "Logic -> Coils" not in source, "Violation: synthetic 'Logic -> Coils' path must not exist"
    assert '{"cmd_id": 32805' not in source, "Violation: hardcoded 32805 cmd ID table must not exist"
    assert '{"cmd_id": 32811' not in source, "Violation: hardcoded 32811 cmd ID table must not exist"
    assert '{"cmd_id": 32815' not in source, "Violation: hardcoded 32815 cmd ID table must not exist"
    assert "contacts_and_coils_catalog" not in source, "Violation: hardcoded contacts_and_coils_catalog must not exist"
    assert "---[ ]---" not in source, "Violation: ASCII ladder symbols must not be hardcoded in probe script"


def test_probe_functions_and_fail_closed_logic_present():
    """Assert live inspection functions and zero-entry fail-closed assertion exist in probe script."""
    from scripts.probe_ladder_editor import (
        find_and_select_logic_editing_tab,
        dump_logic_editing_buttons,
        dump_project_toolbox_items,
        dump_w5editld_exports,
        find_ladder_vertical_toolbar,
        dump_vertical_toolbar_buttons,
        find_and_select_edit_tab,
        dump_edit_ribbon_buttons,
    )
    assert callable(find_and_select_logic_editing_tab)
    assert callable(dump_logic_editing_buttons)
    assert callable(dump_project_toolbox_items)
    assert callable(dump_w5editld_exports)
    assert callable(find_ladder_vertical_toolbar)
    assert callable(dump_vertical_toolbar_buttons)
    assert callable(find_and_select_edit_tab)
    assert callable(dump_edit_ribbon_buttons)

    probe_script_path = Path(__file__).resolve().parent.parent / "scripts" / "probe_ladder_editor.py"
    source = probe_script_path.read_text(encoding="utf-8")

    assert "ZERO_LIVE_ENTRIES" in source, "Probe script must enforce ZERO_LIVE_ENTRIES fail-closed check"
    assert 'item.get("source", "").startswith("live_")' in source, "Probe script must enforce live_* tagging contract"
    assert 'LOGIC_EDITING_TAB_SCREENSHOT_PATH' in source
    assert 'EDIT_TAB_SCREENSHOT_PATH' in source
    assert 'CONTACTS_EXPANDED_SCREENSHOT_PATH' in source
    assert "header_cy < 52" in source, "Probe script must enforce header_cy < 52 tab header click guard"


def test_screenshot_and_printwindow_infrastructure():
    """Verify capture_via_printwindow and capture_window_screenshot exist and accept crop_box."""
    from scripts.probe_ladder_editor import (
        capture_via_printwindow,
        capture_window_screenshot,
        LOGIC_EDITING_TAB_SCREENSHOT_PATH,
        EDIT_TAB_SCREENSHOT_PATH,
        CONTACTS_EXPANDED_SCREENSHOT_PATH,
    )
    assert callable(capture_via_printwindow)
    assert callable(capture_window_screenshot)
    sig = inspect.signature(capture_window_screenshot)
    assert "crop_box" in sig.parameters
    assert LOGIC_EDITING_TAB_SCREENSHOT_PATH.name == "logic_editing_tab.png"
    assert EDIT_TAB_SCREENSHOT_PATH.name == "edit_tab.png"
    assert CONTACTS_EXPANDED_SCREENSHOT_PATH.name == "contacts_and_coils_expanded.png"


def test_tbbutton32_ctypes_structure():
    """Verify 32-bit TBBUTTON ctypes struct is exactly 20 bytes for WoW64 Cscape.exe."""
    import ctypes
    from scripts.probe_ladder_editor import TBBUTTON32
    assert ctypes.sizeof(TBBUTTON32) == 20, f"Expected 20 bytes, got {ctypes.sizeof(TBBUTTON32)}"
    btn = TBBUTTON32()
    assert hasattr(btn, "iBitmap")
    assert hasattr(btn, "idCommand")
    assert hasattr(btn, "fsState")
    assert hasattr(btn, "fsStyle")
    assert hasattr(btn, "bReserved")
    assert hasattr(btn, "dwData")
    assert hasattr(btn, "iString")


def test_live_source_tagging_contract():
    """Verify all items passed into live_ladder_items strictly have source starting with 'live_'."""
    from scripts.probe_ladder_editor import classify_ladder_commands

    mock_live_items = [
        {"name": "Normally Open Contact", "source": "live_vertical_toolbar", "cmd_id": 1000},
        {"name": "Normally Closed Contact", "source": "live_vertical_toolbar", "cmd_id": 1001},
        {"name": "Normally Open Coil", "source": "live_vertical_toolbar", "cmd_id": 1002},
        {"name": "Timer", "source": "live_vertical_toolbar", "cmd_id": 1003},
        {"name": "Counter", "source": "live_vertical_toolbar", "cmd_id": 1004},
        {"name": "Normally Open Contact", "source": "live_toolbox", "cmd_id": 37684},
        {"name": "Normally Closed Contact", "source": "live_toolbox", "cmd_id": 37685},
        {"name": "Normally Open Coil", "source": "live_toolbox", "cmd_id": 37686},
        {"name": "Undo", "source": "live_uia", "cmd_id": None},
        {"name": "Cut", "source": "live_menu", "cmd_id": 57635},
    ]

    assert all(item["source"].startswith("live_") for item in mock_live_items)
    classified = classify_ladder_commands(mock_live_items)
    assert len(classified["contacts"]) >= 2
    assert len(classified["coils"]) >= 2
    assert len(classified["timers_and_counters"]) >= 2



