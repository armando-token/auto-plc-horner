# -*- coding: utf-8 -*-
"""Unit and Contract Tests for Gate G8 HMI Object Placement & Variable Binding Roundtrip.

Enforces:
1. Syntax and AST validation of scripts/g8_bind_roundtrip.py.
2. Zero hardcoded HWNDs / PID contract.
3. Strict fail-closed safety invariants and COM port lockout.
4. Native CFBF /Contents stream parsing and negative control oracle delta (0 -> 1 object count).
5. Dynamic dialog handling (Dialog 173 and Dialog 108) and variable binding.
6. Reopen verification and screen editor class assertion (HornerAPGTabbedGraphicsEditor).
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
import shutil
from typing import Any, Dict, List
import unittest.mock as mock

import pytest
import win32con
import win32gui

from scripts.g8_bind_roundtrip import (
    BASE_P1_PATH,
    BASELINE_P1_SHA,
    DEFAULT_TARGET_VAR,
    FALLBACK_INT_VAR,
    ID_INSERT_NUMERIC_DATA,
    ID_FILE_SAVE,
    assert_safety_invariants,
    compute_cfbf_hmi_delta,
    compute_sha256,
    handle_confirmation_popups,
    handle_hmi_binding_dialog,
    parse_cfbf_hmi_elements,
    place_numeric_display_on_screen,
    verify_cfbf_hmi_proof,
)


def test_g8_bind_roundtrip_syntax_and_ast():
    """Verify scripts/g8_bind_roundtrip.py parses as valid Python AST without syntax errors."""
    script_path = Path("scripts/g8_bind_roundtrip.py")
    assert script_path.exists(), f"{script_path} must exist"
    content = script_path.read_text(encoding="utf-8")
    tree = ast.parse(content, filename=str(script_path))
    assert tree is not None
    assert isinstance(tree, ast.Module)


def test_g8_bind_roundtrip_zero_hardcoded_ids_contract():
    """Verify zero hardcoded HWNDs or process IDs are present in scripts/g8_bind_roundtrip.py."""
    script_path = Path("scripts/g8_bind_roundtrip.py")
    content = script_path.read_text(encoding="utf-8")
    # Verify no hardcoded runtime HWND constants
    assert "HWND_DESKTOP =" not in content
    assert "HARDCODED_HWND" not in content
    assert "HARDCODED_PID" not in content
    # Assert ID_INSERT_NUMERIC_DATA is 7610 (MFC command ID in GrEdit.dll)
    assert ID_INSERT_NUMERIC_DATA == 7610
    assert ID_FILE_SAVE == 57603


def test_g8_bind_roundtrip_safety_invariants():
    """Verify fail-closed safety assertions protect baseline p1_base.csp immutability."""
    assert BASE_P1_PATH.exists()
    current_sha = compute_sha256(BASE_P1_PATH)
    assert current_sha == BASELINE_P1_SHA, "Baseline p1_base.csp must match canonical SHA-256"
    assert_safety_invariants()


def test_parse_cfbf_hmi_elements_negative_control():
    """Verify parse_cfbf_hmi_elements on baseline p1_base.csp detects 0 objects and no bound variable."""
    base_info = parse_cfbf_hmi_elements(BASE_P1_PATH, target_var=DEFAULT_TARGET_VAR)
    assert base_info["exists"] is True
    assert base_info["graphics_offset"] != -1
    assert base_info["screen_width"] == 320
    assert base_info["screen_height"] == 240
    assert base_info["object_count"] == 0
    assert base_info["target_var_found"] is False
    assert len(base_info["objects"]) == 0


def test_parse_cfbf_hmi_elements_detects_objects_and_bindings(monkeypatch, tmp_path):
    """Verify parse_cfbf_hmi_elements correctly detects object count and target variable presence."""
    # Create a synthetic CFBF file with Graphics section and target var
    import olefile

    test_csp = tmp_path / "mock_placed.csp"
    
    # Read real p1_base.csp stream
    ole_in = olefile.OleFileIO(str(BASE_P1_PATH))
    real_stream = bytearray(ole_in.openstream("Contents").read())
    ole_in.close()

    # Modify graphics section in synthetic copy
    g_idx = real_stream.find(b"Graphics\x00")
    assert g_idx != -1
    
    # Set object count = 1 at g_idx + 44
    real_stream[g_idx + 44 : g_idx + 46] = (1).to_bytes(2, "little")
    # Append target variable name into graphics section
    var_bytes = DEFAULT_TARGET_VAR.encode("latin1")
    real_stream[g_idx + 100 : g_idx + 100 + len(var_bytes)] = var_bytes

    # Write synthetic file
    with open(test_csp, "wb") as f:
        # Create minimal OLE with Contents stream
        shutil.copy2(BASE_P1_PATH, test_csp)

    # Use monkeypatch to return mock stream
    class MockOle:
        def __init__(self, *args, **kwargs):
            pass
        def openstream(self, name):
            class MockStream:
                def read(self):
                    return bytes(real_stream)
            return MockStream()
        def close(self):
            pass

    monkeypatch.setattr(olefile, "OleFileIO", MockOle)

    info = parse_cfbf_hmi_elements(test_csp, target_var=DEFAULT_TARGET_VAR)
    assert info["object_count"] >= 1
    assert info["target_var_found"] is True
    assert len(info["objects"]) >= 1
    assert info["objects"][0]["binding"] == DEFAULT_TARGET_VAR


def test_compute_cfbf_hmi_delta():
    """Verify compute_cfbf_hmi_delta computes exact positive object delta (0 -> 1)."""
    base_info = {
        "file_path": "base.csp",
        "object_count": 0,
        "target_var_found": False,
        "objects": [],
    }
    roundtrip_info = {
        "file_path": "roundtrip.csp",
        "object_count": 1,
        "target_var_found": True,
        "objects": [{"type": "Numeric Display", "binding": "G3_TEST_VAR_01", "offset": 1234}],
    }

    delta = compute_cfbf_hmi_delta(base_info, roundtrip_info)
    assert delta["base_object_count"] == 0
    assert delta["roundtrip_object_count"] == 1
    assert delta["delta_object_count"] == 1
    assert delta["base_target_var_found"] is False
    assert delta["roundtrip_target_var_found"] is True
    assert len(delta["new_objects"]) == 1


def test_verify_cfbf_hmi_proof_success_and_failure(monkeypatch, tmp_path):
    """Verify verify_cfbf_hmi_proof returns success when delta >= 1 and fails when unchanged."""
    test_csp = tmp_path / "mock_roundtrip.csp"
    shutil.copy2(BASE_P1_PATH, test_csp)
    initial_sha = "initial_fake_sha"

    # Mock parse_cfbf_hmi_elements to return success
    def mock_parse(p, target_var):
        if str(p) == str(BASE_P1_PATH):
            return {"file_path": str(p), "object_count": 0, "target_var_found": False, "objects": []}
        return {"file_path": str(p), "object_count": 1, "target_var_found": True, "objects": [{"type": "Numeric Display"}]}

    monkeypatch.setattr("scripts.g8_bind_roundtrip.parse_cfbf_hmi_elements", mock_parse)
    monkeypatch.setattr("scripts.g8_bind_roundtrip.compute_sha256", lambda p: "new_saved_sha" if "mock" in str(p) else BASELINE_P1_SHA)

    proof = verify_cfbf_hmi_proof(test_csp, target_var=DEFAULT_TARGET_VAR, initial_sha=initial_sha)
    assert proof["status"] == "success"
    assert proof["sha_changed"] is True
    assert proof["delta_object_count"] == 1
    assert proof["target_var_found"] is True

    # Test failure case when SHA unchanged
    proof_fail = verify_cfbf_hmi_proof(test_csp, target_var=DEFAULT_TARGET_VAR, initial_sha="new_saved_sha")
    assert proof_fail["status"] == "failed"
    assert "SHA-256 unchanged" in proof_fail.get("error", "")


def test_handle_hmi_binding_dialog_with_dialog173(monkeypatch):
    """Verify handle_hmi_binding_dialog sets variable text and clicks OK on Dialog 173."""
    dispatched_msgs = []
    clicked_buttons = []

    # Mock dialog detection
    monkeypatch.setattr("scripts.g8_bind_roundtrip.find_hmi_property_dialog", lambda pid, timeout: 0x9000)
    monkeypatch.setattr(win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(win32gui, "IsWindowVisible", lambda h: False if h == 0x9000 and len(clicked_buttons) > 0 else True)
    monkeypatch.setattr(win32gui, "GetWindowText", lambda h: "Numeric Data Properties" if h == 0x9000 else "")
    monkeypatch.setattr("scripts.g8_bind_roundtrip.user32.SetForegroundWindow", lambda h: True)

    # Mock dump_child_windows_recursive to return Edit control 1500
    mock_children = [
        {"hwnd": 0x9010, "class_name": "Edit", "control_id": 1441, "title": ""},
        {"hwnd": 0x9020, "class_name": "Button", "control_id": 1, "title": "OK"},
    ]
    monkeypatch.setattr("scripts.g8_bind_roundtrip.dump_child_windows_recursive", lambda h: mock_children)
    monkeypatch.setattr(
        "scripts.g8_bind_roundtrip.user32.SendMessageW",
        lambda h, msg, wp, lp: dispatched_msgs.append((h, msg, lp)),
    )
    monkeypatch.setattr(
        "scripts.g8_bind_roundtrip.user32.GetDlgItem",
        lambda h, cid: 0x9020 if cid == 1 else (0x9010 if cid == 1441 else 0),
    )
    monkeypatch.setattr(
        "scripts.g8_bind_roundtrip.user32.PostMessageW",
        lambda h, msg, wp, lp: clicked_buttons.append((h, msg, wp)),
    )

    evidence = {}
    res = handle_hmi_binding_dialog(1234, 0x1000, "G3_TEST_VAR_01", evidence=evidence, timeout=1.0)
    assert res is True
    # WM_SETTEXT (12) sent with target variable
    assert any(m[1] == win32con.WM_SETTEXT and m[2] == "G3_TEST_VAR_01" for m in dispatched_msgs)
    # BM_CLICK (245) or WM_COMMAND sent to OK button
    assert len(clicked_buttons) > 0


def test_handle_confirmation_popups(monkeypatch):
    """Verify handle_confirmation_popups finds and clicks Yes/OK on popup dialogs."""
    clicked = []

    def mock_enum(cb, extra):
        cb(0x9500, extra)

    monkeypatch.setattr(win32gui, "EnumWindows", mock_enum)
    monkeypatch.setattr(win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(win32gui, "IsWindowVisible", lambda h: True)
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "#32770")
    monkeypatch.setattr(win32gui, "GetWindowText", lambda h: "Create Variable?")
    monkeypatch.setattr("win32process.GetWindowThreadProcessId", lambda h: (1, 1234))
    monkeypatch.setattr("scripts.g8_bind_roundtrip.user32.GetDlgItem", lambda h, cid: 0x9506 if cid == 6 else 0)
    monkeypatch.setattr(
        "scripts.g8_bind_roundtrip.user32.PostMessageW",
        lambda h, msg, wp, lp: clicked.append((h, msg, wp)),
    )

    handled = handle_confirmation_popups(1234, timeout=0.5)
    assert handled is True
    assert len(clicked) > 0
    # Clicked Yes button (ID 6)
    assert any(c[1] == win32con.BM_CLICK for c in clicked)


def test_place_numeric_display_on_screen_dispatches_7610(monkeypatch):
    """Verify place_numeric_display_on_screen dispatches command 7610 and mouse clicks."""
    dispatched_commands = []
    mouse_actions = []

    monkeypatch.setattr(win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(win32gui, "GetWindowRect", lambda h: (100, 100, 500, 400))
    monkeypatch.setattr("scripts.g8_bind_roundtrip.user32.SetForegroundWindow", lambda h: True)
    monkeypatch.setattr("scripts.g8_bind_roundtrip.user32.ScreenToClient", lambda h, pt: None)
    monkeypatch.setattr(
        "scripts.g8_bind_roundtrip.user32.SendMessageW",
        lambda h, msg, wp, lp: dispatched_commands.append((h, msg, wp)),
    )
    monkeypatch.setattr("pywinauto.mouse.click", lambda coords: mouse_actions.append(("click", coords)))
    monkeypatch.setattr("scripts.g8_bind_roundtrip.handle_hmi_binding_dialog", lambda *args, **kwargs: True)
    monkeypatch.setattr("scripts.g8_bind_roundtrip.capture_window_screenshot", lambda h, p: True)

    evidence = {}
    res = place_numeric_display_on_screen(0x1000, 0x2000, 1234, "G3_TEST_VAR_01", evidence=evidence)
    assert res["placed"] is True
    assert res["property_dialog_handled"] is True
    assert res["canvas_coords"] == [300, 250]
    # Check that WM_COMMAND (273) with ID_INSERT_NUMERIC_DATA (7610) was dispatched
    assert any(cmd[1] == win32con.WM_COMMAND and cmd[2] == ID_INSERT_NUMERIC_DATA for cmd in dispatched_commands)
    # Check mouse click at canvas center (300, 250)
    assert any(m[0] == "click" and m[1] == (300, 250) for m in mouse_actions)


def test_run_g8_bind_roundtrip_fails_closed_on_ladder_editor(monkeypatch, tmp_path):
    """Verify run_g8_bind_roundtrip strictly raises RuntimeError if ladder editor is resolved."""
    from scripts.g8_bind_roundtrip import run_g8_bind_roundtrip

    test_copy = tmp_path / "test_copy.csp"
    shutil.copy2(BASE_P1_PATH, test_copy)

    monkeypatch.setattr("scripts.g8_bind_roundtrip.configure_cscape_registry", lambda p: None)
    monkeypatch.setattr("scripts.g8_bind_roundtrip.kill_leftover_cscape", lambda: None)

    class MockApp:
        def window(self, **kwargs):
            class MockWin:
                def set_focus(self): pass
            return MockWin()

    monkeypatch.setattr("scripts.g8_bind_roundtrip.launch_cscape_with_project", lambda p: (MockApp(), 1234, 0x1000))
    monkeypatch.setattr("scripts.g8_bind_roundtrip.handle_startup_dialogs_and_wait_for_main_window", lambda **kwargs: None)
    # Return ladder logic editor (CW5EditLDWnd) which must fail closed
    monkeypatch.setattr(
        "scripts.g8_bind_roundtrip.open_screen_editor_dynamic",
        lambda main_h, pid, app_u, ev: (0x3000, "ladder_editor"),
    )
    monkeypatch.setattr("scripts.g8_bind_roundtrip.is_screen_editor_window", lambda h: False)

    with pytest.raises(RuntimeError, match="FAIL_CLOSED: Resolved window.*is NOT the Screen Editor"):
        run_g8_bind_roundtrip(
            target_var=DEFAULT_TARGET_VAR,
            target_copy=test_copy,
            evidence_path=tmp_path / "test_evidence.json",
        )
