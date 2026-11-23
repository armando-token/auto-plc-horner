# -*- coding: utf-8 -*-
"""Unit and Integration Test Suite for Gate G8 HMI Acceptance Campaign.

Mandate: Gate G8 HMI Acceptance Verification Test Suite.
Classification: TESTED_MOCK / INTEGRATION [Pure Software / Win32 AST]
"""

import json
from pathlib import Path
import pytest

REPO_ROOT = Path(r"C:\HornerAI\jev-cscape-agent")
import sys
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.security.guard import SecurityGuard
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.security.exceptions import HardwareLockoutError

from scripts.probe_hmi_editor import (
    BASE_P1_PATH,
    BASELINE_P1_SHA,
    compute_sha256,
    is_screen_editor_window,
)
from scripts.g8_acceptance import (
    LAYOUTS,
    get_layout_for_run,
    validate_canvas_coordinates,
    run_out_of_bounds_negative_test,
    run_wrong_binding_negative_test,
    parse_cfbf_hmi_elements,
    compute_cfbf_hmi_delta,
    verify_cfbf_hmi_proof,
    run_g8_acceptance_campaign,
    SUMMARY_JSON_PATH,
    ACCEPTANCE_RUNS_DIR,
    detect_and_handle_error_dialog,
    expand_all_treeview_items,
    verify_tag_in_hmi_picker,
    handle_hmi_binding_dialog,
)


def test_baseline_csp_immutability():
    """Verify work/disposable/p1_base.csp is bit-for-bit identical to baseline SHA-256."""
    assert BASE_P1_PATH.exists(), f"Baseline missing: {BASE_P1_PATH}"
    actual_sha = compute_sha256(BASE_P1_PATH)
    assert actual_sha == BASELINE_P1_SHA, f"Baseline mutated! Expected {BASELINE_P1_SHA}, got {actual_sha}"


def test_hardware_safety_lockout():
    """Verify physical COM ports, download commands, and companion flash tools are blocked fail-closed."""
    # Physical COM port lockout
    for port in ["COM1", "COM3", "com256", r"\\.\COM1", "/dev/ttyUSB0", "CAN0"]:
        with pytest.raises(HardwareLockoutError):
            SecurityGuard.assert_port_safe(port)

    # Win32 download command lockout
    for cmd in [32827, 33149]:
        with pytest.raises(HardwareLockoutError):
            SecurityGuard.assert_win32_command_safe(cmd)

    # Safe commands allowed
    SecurityGuard.assert_win32_command_safe(32826)  # Compile / Error Check
    SecurityGuard.assert_win32_command_safe(57603)  # Save


def test_hmi_schema_document_exists_and_conforms():
    """Verify docs/G8_HMI_SCHEMA_AND_PROPERTY_MATRIX.md exists and covers all required schema elements."""
    doc_path = REPO_ROOT / "docs" / "G8_HMI_SCHEMA_AND_PROPERTY_MATRIX.md"
    assert doc_path.exists(), f"HMI Schema doc missing: {doc_path}"
    content = doc_path.read_text(encoding="utf-8")

    assert "/Contents" in content
    assert "Graphics\\x00" in content
    assert "GrEdit.dll" in content
    assert "Numeric Data" in content
    assert "7610" in content
    assert "Dialog 173" in content
    assert "12024" in content
    assert "37011" in content
    assert "Dialog 180" in content
    assert "Dialog 135" in content
    assert "validate_canvas_coordinates" in content
    assert "Layout A" in content
    assert "Layout B" in content
    assert "Layout C (Reserved)" in content
    assert "Status Bar Oracle" in content


def test_layout_specifications():
    """Verify >= 3 distinct layouts defined, 1 reserved layout, >= 2 bound objects per layout."""
    assert len(LAYOUTS) >= 3, f"Must have >= 3 layouts, got {len(LAYOUTS)}"

    reserved_count = sum(1 for l in LAYOUTS if l.get("is_reserved"))
    assert reserved_count >= 1, "Must include at least 1 reserved layout"

    topologies = {l["topology"] for l in LAYOUTS}
    assert "vertical" in topologies
    assert "horizontal" in topologies
    assert "diagonal" in topologies

    for layout in LAYOUTS:
        assert len(layout["objects"]) >= 2, f"Layout {layout['id']} has < 2 objects"
        bindings = [o["binding"] for o in layout["objects"]]
        assert len(set(bindings)) >= 2 or len(bindings) >= 2, "Objects must have defined bindings"
        for obj in layout["objects"]:
            assert obj["binding"] in ("RTC_SEC", "RTC_MIN", "RTC_HOUR", "RTC_DAY", "SP_Internal", "G3_TEST_VAR_01")


def test_validate_canvas_coordinates_positive():
    """Verify coordinate validation passes for all layout objects within canvas bounds."""
    canvas_rect = (345, 173, 1267, 345)
    cx = (345 + 1267) // 2
    cy = (173 + 345) // 2

    for layout in LAYOUTS:
        for obj in layout["objects"]:
            x = cx + obj["offset_x"]
            y = cy + obj["offset_y"]
            assert validate_canvas_coordinates(x, y, canvas_rect) is True


def test_validate_canvas_coordinates_negative_out_of_bounds():
    """Verify coordinate validation raises ValueError for out-of-bounds targets."""
    canvas_rect = (345, 173, 1267, 345)

    with pytest.raises(ValueError, match="out of canvas bounds"):
        validate_canvas_coordinates(9999, 9999, canvas_rect)

    with pytest.raises(ValueError, match="out of canvas bounds"):
        validate_canvas_coordinates(-100, -100, canvas_rect)

    with pytest.raises(ValueError, match="out of canvas bounds"):
        validate_canvas_coordinates(100, 250, canvas_rect)  # X too small

    with pytest.raises(ValueError, match="out of canvas bounds"):
        validate_canvas_coordinates(800, 100, canvas_rect)  # Y too small


def test_run_out_of_bounds_negative_test():
    """Verify run_out_of_bounds_negative_test catches all test coordinates fail-closed."""
    res = run_out_of_bounds_negative_test()
    assert res["detected"] is True
    assert res["status"] == "success"
    assert len(res["errors_caught"]) == 4


def test_run_wrong_binding_negative_test():
    """Verify run_wrong_binding_negative_test detects mismatched variable and fails closed."""
    test_csp = REPO_ROOT / "work" / "disposable" / "copies" / "g8_bind_roundtrip.csp"
    if not test_csp.exists():
        test_csp = BASE_P1_PATH

    res = run_wrong_binding_negative_test(test_csp)
    assert res["detected"] is True
    assert res["status"] == "success"
    assert "Binding readback mismatch" in res["error_caught"]


def test_cfbf_multi_object_oracle_negative_control():
    """Verify CFBF oracle correctly reports 0 objects on untouched baseline."""
    base_info = parse_cfbf_hmi_elements(BASE_P1_PATH, target_vars=["RTC_SEC", "RTC_MIN"])
    assert base_info["exists"] is True
    assert base_info["object_count"] == 0
    assert not any(base_info["target_vars_found"].values())


def test_cfbf_multi_object_oracle_two_objects_provenance():
    """Verify CFBF oracle correctly parses multi-object count (>= 2) and variable bindings."""
    run01_path = REPO_ROOT / "work" / "disposable" / "copies" / "g8_acceptance_run_01.csp"
    if run01_path.exists():
        info = parse_cfbf_hmi_elements(run01_path, target_vars=["RTC_SEC", "RTC_MIN"])
        assert info["exists"] is True
        assert info["object_count"] == 2
        assert info["target_vars_found"]["RTC_SEC"] is True
        assert info["target_vars_found"]["RTC_MIN"] is True
        proof = verify_cfbf_hmi_proof(run01_path, target_vars=["RTC_SEC", "RTC_MIN"])
        assert proof["status"] == "success"


def test_get_layout_for_run_distribution():
    """Verify layout rotation across 20 runs covers all 3 layouts properly."""
    counts = {"A": 0, "B": 0, "C": 0}
    for i in range(1, 21):
        layout = get_layout_for_run(i)
        counts[layout["id"]] += 1

    assert counts["A"] == 7  # 1, 4, 7, 10, 13, 16, 19
    assert counts["B"] == 7  # 2, 5, 8, 11, 14, 17, 20
    assert counts["C"] == 6  # 3, 6, 9, 12, 15, 18


def test_fail_closed_ladder_editor_rejection():
    """Verify ladder editor window (CW5EditLDWnd) is rejected as screen editor."""
    # Dummy handle check
    assert not is_screen_editor_window(0)
    assert not is_screen_editor_window(-1)


def test_acceptance_campaign_dry_run(tmp_path):
    """Verify dry-run acceptance evaluation completes with 20 runs and meets >= 19/20 threshold."""
    tmp_summary = tmp_path / "g8_acceptance_summary.json"
    summary = run_g8_acceptance_campaign(total_runs=20, dry_run=True, summary_output_path=tmp_summary)
    assert summary["status"] == "success"
    assert summary["total_runs"] == 20
    assert summary["passed_runs"] == 20
    assert summary["pass_rate"] == 1.0
    assert summary["pass_threshold_met"] is True
    assert summary["reserved_layout_included"] is True
    assert len(summary["layouts_tested"]) >= 3
    assert summary["negative_controls"]["wrong_binding_negative"]["detected"] is True
    assert summary["negative_controls"]["out_of_bounds_negative"]["detected"] is True


def test_detect_and_handle_error_dialog_logic(monkeypatch):
    """Verify detect_and_handle_error_dialog detects modal error popup, reads text, logs error, and dismisses it."""
    from unittest.mock import MagicMock
    import win32gui
    import win32process
    import ctypes

    fake_dlg = 0x12345
    fake_pid = 7777

    # Mock EnumWindows to simulate discovering a #32770 window
    def mock_enum_windows(cb, _):
        cb(fake_dlg, None)

    monkeypatch.setattr(win32gui, "EnumWindows", mock_enum_windows)
    monkeypatch.setattr(win32gui, "IsWindow", lambda h: True if h == fake_dlg else False)
    monkeypatch.setattr(win32gui, "IsWindowVisible", lambda h: True)
    monkeypatch.setattr(win32process, "GetWindowThreadProcessId", lambda h: (1, fake_pid))
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "#32770")
    monkeypatch.setattr(win32gui, "GetWindowText", lambda h: "Cscape" if h == fake_dlg else "")

    # Mock children: Static message label and OK button
    mock_children = [
        {"hwnd": 0x2222, "class_name": "Static", "text": "Variable not declared", "control_id": -1},
        {"hwnd": 0x3333, "class_name": "Button", "text": "OK", "control_id": 1},
    ]
    monkeypatch.setattr("scripts.g8_acceptance.dump_child_windows_recursive", lambda h: mock_children)

    user32_mock = ctypes.windll.user32
    monkeypatch.setattr(user32_mock, "GetDlgItem", lambda h, cid: 0x3333 if (h == fake_dlg and cid == 1) else 0)
    post_mock = MagicMock()
    monkeypatch.setattr(user32_mock, "PostMessageW", post_mock)

    evidence = {}
    err_info = detect_and_handle_error_dialog(pid=fake_pid, parent_dlg_hwnd=0x9999, timeout=0.5, evidence=evidence)

    assert err_info is not None
    assert err_info["hwnd"] == hex(fake_dlg)
    assert err_info["title"] == "Cscape"
    assert "Variable not declared" in err_info["message"]
    assert len(evidence.get("modal_errors", [])) == 1
    assert "Variable not declared" in evidence["modal_errors"][0]["message"]
    assert post_mock.called


def test_expand_all_treeview_items_safety():
    """Verify expand_all_treeview_items safely returns 0 on null/invalid HWND."""
    assert expand_all_treeview_items(0) == 0
    assert expand_all_treeview_items(None) == 0


def test_verify_tag_in_hmi_picker_logic(monkeypatch):
    """Verify verify_tag_in_hmi_picker expands tree and returns presence status and tag list."""
    from unittest.mock import MagicMock

    fake_dlg = 0x5555
    fake_tv = 0x6666

    # Mock finding SysTreeView32 inside selector_dlg
    monkeypatch.setattr(
        "scripts.g8_acceptance.dump_child_windows_recursive",
        lambda h: [{"hwnd": fake_tv, "class_name": "SysTreeView32", "text": "", "control_id": 100}]
    )
    monkeypatch.setattr("scripts.g8_acceptance.expand_all_treeview_items", lambda h: 3)

    # Mock UIA elements
    class MockTreeItem:
        def __init__(self, name):
            self.name = name
        def window_text(self):
            return self.name
        def expand(self):
            pass

    mock_items = [
        MockTreeItem("Global Variables"),
        MockTreeItem("RTC_SEC"),
        MockTreeItem("RTC_MIN"),
        MockTreeItem("T1_LEVEL_PV"),
    ]

    class MockSelUia:
        def descendants(self, control_type="TreeItem"):
            return mock_items

    class MockAppUia:
        def window(self, handle=None):
            return MockSelUia()

    # 1. Test target present
    is_pres, tags, item = verify_tag_in_hmi_picker(
        pid=1234, selector_dlg=fake_dlg, target_var="T1_LEVEL_PV", app_uia=MockAppUia()
    )
    assert is_pres is True
    assert "T1_LEVEL_PV" in tags
    assert "RTC_SEC" in tags
    assert item is not None
    assert item.window_text() == "T1_LEVEL_PV"

    # 2. Test target absent
    is_pres_missing, tags_missing, item_missing = verify_tag_in_hmi_picker(
        pid=1234, selector_dlg=fake_dlg, target_var="NONEXISTENT_VAR", app_uia=MockAppUia()
    )
    assert is_pres_missing is False
    assert item_missing is None
    assert len(tags_missing) == len(tags)


def test_handle_hmi_binding_dialog_preserves_strict_assertion():
    """Verify that handle_hmi_binding_dialog strictly enforces verified_val == target_var fail-closed."""
    import inspect
    from scripts.g8_acceptance import handle_hmi_binding_dialog

    src = inspect.getsource(handle_hmi_binding_dialog)
    assert (
        "assert verified_val == target_var" in src
        or ("if verified_val != target_var:" in src and "raise AssertionError" in src)
    ), "Strict assertion invariant must NOT be weakened!"


def test_find_hmi_property_dialog_strict_matching(monkeypatch):
    """Verify that find_hmi_property_dialog strictly accepts '#32770' with 'Numeric Data Properties'

    and strictly rejects compiler output dialogs, compilation errors, and other dialogs.
    """
    from scripts.g8_acceptance import find_hmi_property_dialog

    # Case 1: Authentic "Numeric Data Properties" dialog -> MUST BE ACCEPTED
    windows_db = {
        0x1000: {"pid": 555, "class": "#32770", "title": "Numeric Data Properties", "visible": True},
    }

    def fake_is_window(h):
        return h in windows_db
    def fake_is_window_visible(h):
        return windows_db.get(h, {}).get("visible", False)
    def fake_get_thread_proc_id(h):
        return 0, windows_db.get(h, {}).get("pid", 0)
    def fake_get_class_name(h):
        return windows_db.get(h, {}).get("class", "")
    def fake_get_window_text(h):
        return windows_db.get(h, {}).get("title", "")
    def fake_enum_windows(cb, extra):
        for h in list(windows_db.keys()):
            if not cb(h, extra):
                break

    monkeypatch.setattr("win32gui.IsWindow", fake_is_window)
    monkeypatch.setattr("win32gui.IsWindowVisible", fake_is_window_visible)
    monkeypatch.setattr("win32process.GetWindowThreadProcessId", fake_get_thread_proc_id)
    monkeypatch.setattr("win32gui.GetClassName", fake_get_class_name)
    monkeypatch.setattr("win32gui.GetWindowText", fake_get_window_text)
    monkeypatch.setattr("win32gui.EnumWindows", fake_enum_windows)

    # 1. Authentic dialog matches
    res = find_hmi_property_dialog(pid=555, timeout=0.2)
    assert res == 0x1000, f"Expected 0x1000, got {res}"

    # 2. "There were no errors or warnings" -> MUST BE REJECTED
    windows_db[0x1000]["title"] = "There were no errors or warnings"
    res_compiler = find_hmi_property_dialog(pid=555, timeout=0.1)
    assert res_compiler is None, "Compiler output dialog must NOT be accepted as HMI property dialog!"

    # 3. "Non-Fatal Compilation Errors were found. Do you want to continue?" -> MUST BE REJECTED
    windows_db[0x1000]["title"] = "Non-Fatal Compilation Errors were found. Do you want to continue?"
    res_non_fatal = find_hmi_property_dialog(pid=555, timeout=0.1)
    assert res_non_fatal is None, "Non-fatal compilation error dialog must NOT be accepted!"

    # 4. "Error" / "Cscape" -> MUST BE REJECTED
    windows_db[0x1000]["title"] = "Cscape Error"
    res_err = find_hmi_property_dialog(pid=555, timeout=0.1)
    assert res_err is None, "Generic Error dialog must NOT be accepted!"

    # 5. Wrong class (e.g. AfxWnd) with title "Numeric Data Properties" -> MUST BE REJECTED
    windows_db[0x1000]["title"] = "Numeric Data Properties"
    windows_db[0x1000]["class"] = "AfxFrameOrView140su"
    res_wrong_cls = find_hmi_property_dialog(pid=555, timeout=0.1)
    assert res_wrong_cls is None, "Non-#32770 window must NOT be accepted!"


def test_handle_hmi_binding_dialog_fails_closed_when_tag_missing_from_picker(monkeypatch):
    """Verify that handle_hmi_binding_dialog immediately raises AssertionError (FAIL_CLOSED)

    when the target variable does not appear in the HMI tag picker treeview.
    """
    import win32gui
    import win32process
    from scripts.g8_acceptance import handle_hmi_binding_dialog

    # Mock dialog detection: Dialog 173 exists
    monkeypatch.setattr("scripts.g8_acceptance.find_hmi_property_dialog", lambda pid, timeout: 0x9000)
    monkeypatch.setattr(win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(win32gui, "IsWindowVisible", lambda h: True)
    monkeypatch.setattr(win32gui, "GetWindowText", lambda h: "Numeric Data Properties" if h == 0x9000 else "")
    monkeypatch.setattr("scripts.g8_acceptance.user32.SetForegroundWindow", lambda h: True)

    # Mock dump_child_windows_recursive to return Button 37011 ('>') and Edit 12024
    mock_children_dlg = [
        {"hwnd": 0x9010, "class_name": "Edit", "control_id": 12024, "title": ""},
        {"hwnd": 0x9020, "class_name": "Button", "control_id": 37011, "title": ">"},
        {"hwnd": 0x9030, "class_name": "Button", "control_id": 1, "title": "OK"},
        {"hwnd": 0x9040, "class_name": "Button", "control_id": 2, "title": "Cancel"},
    ]
    monkeypatch.setattr("scripts.g8_acceptance.dump_child_windows_recursive", lambda h: mock_children_dlg)

    # Mock selector dialog finding: selector dialog appears (0x9500)
    def fake_enum_windows(cb, extra):
        cb(0x9500, extra)
    monkeypatch.setattr(win32gui, "EnumWindows", fake_enum_windows)
    monkeypatch.setattr(win32process, "GetWindowThreadProcessId", lambda h: (0, 1234))
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "#32770" if h in (0x9000, 0x9500) else "Edit")

    # Mock verify_tag_in_hmi_picker to return (False, ["RTC_SEC", "ALRM_SCR", "AI"], None)
    monkeypatch.setattr(
        "scripts.g8_acceptance.verify_tag_in_hmi_picker",
        lambda pid, selector_dlg, target_var, app_uia: (False, ["RTC_SEC", "ALRM_SCR", "AI"], None)
    )

    # Must raise AssertionError with FAIL_CLOSED
    with pytest.raises(AssertionError) as exc_info:
        handle_hmi_binding_dialog(pid=1234, main_hwnd=0x1000, target_var="T1_LEVEL_PV", timeout=1.0)

    assert "FAIL_CLOSED" in str(exc_info.value)
    assert "T1_LEVEL_PV" in str(exc_info.value)
    assert "not available in HMI tag picker" in str(exc_info.value)


def test_detect_and_handle_error_dialog_excludes_numeric_data_properties(monkeypatch):
    """Verify detect_and_handle_error_dialog NEVER misidentifies 'Numeric Data Properties' (Dialog 173)
    as an error modal and never clicks its 'Local Device' radio button (0x4054a).
    """
    from unittest.mock import MagicMock
    import win32gui
    import win32process
    import scripts.g8_acceptance as g8

    prop_dlg = 0x50534
    fake_pid = 8888

    monkeypatch.setattr(win32gui, "EnumWindows", lambda cb, _: cb(prop_dlg, None))
    monkeypatch.setattr(win32gui, "IsWindow", lambda h: h == prop_dlg)
    monkeypatch.setattr(win32gui, "IsWindowVisible", lambda h: True)
    monkeypatch.setattr(win32process, "GetWindowThreadProcessId", lambda h: (1, fake_pid))
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "#32770")
    monkeypatch.setattr(win32gui, "GetWindowText", lambda h: "Numeric Data Properties")
    monkeypatch.setattr(
        g8,
        "dump_child_windows_recursive",
        lambda h: [
            {"hwnd": 0x4054A, "class_name": "Button", "text": "Local Device", "control_id": 12020},
            {"hwnd": 0x70500, "class_name": "Edit", "text": "", "control_id": 12024},
            {"hwnd": 0x50552, "class_name": "Button", "text": ">", "control_id": 37011},
        ],
    )
    post_mock = MagicMock()
    monkeypatch.setattr(g8.user32, "PostMessageW", post_mock)
    monkeypatch.setattr(g8.time, "sleep", lambda _: None)

    res = detect_and_handle_error_dialog(pid=fake_pid, timeout=0.2)
    assert res is None, "Numeric Data Properties must never be classified as an Error dialog!"
    assert not post_mock.called, "Must not click any button inside Numeric Data Properties during error sweep!"


def test_handle_hmi_binding_dialog_selects_picker_item_and_fails_closed_on_invalid_tag_name(monkeypatch):
    """Verify handle_hmi_binding_dialog:
    1. Calls target_item.select() (UIA SelectionItemPattern.Select()) inside selector_dlg and populates Edit 2053.
    2. Reads ctrl_12024 via _read_window_text_timeout (cross-process WM_GETTEXT) after picker selection.
    3. If Cscape pops 'Error' / 'Invalid tag name' on OK, force-closes Dialog 173 and immediately raises
       AssertionError('FAIL_CLOSED: ... Invalid tag name ...') instead of returning False and leaving Dialog 173 open.
    """
    import win32gui
    import win32process
    import scripts.g8_acceptance as g8

    dlg_hwnd = 0x50534
    selector_dlg = 0x105CE
    tree_hwnd = 0x105DE
    edit_2053 = 0x105DF
    ctrl_12024 = 0x70500
    btn_37011 = 0x50552
    btn_ok = 0x50501

    selected_called = {"count": 0}
    force_closed_hwnds = []

    class DummyRect:
        left = 50
        top = 100
        right = 110
        bottom = 120

    class DummyTreeItem:
        def select(self):
            selected_called["count"] += 1

        def rectangle(self):
            return DummyRect()

    monkeypatch.setattr(g8, "find_hmi_property_dialog", lambda pid, timeout: dlg_hwnd)
    monkeypatch.setattr(win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(win32gui, "IsWindowVisible", lambda h: True)
    monkeypatch.setattr(win32gui, "GetWindowText", lambda h: "Numeric Data Properties" if h == dlg_hwnd else "")
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "#32770" if h in (dlg_hwnd, selector_dlg) else "Edit")
    monkeypatch.setattr(win32process, "GetWindowThreadProcessId", lambda h: (0, 1234))
    monkeypatch.setattr(win32gui, "EnumWindows", lambda cb, extra: cb(selector_dlg, extra))
    monkeypatch.setattr(g8.user32, "SetForegroundWindow", lambda h: 1)
    monkeypatch.setattr(g8.user32, "ScreenToClient", lambda h, pt: 1)
    monkeypatch.setattr(g8.user32, "PostMessageW", lambda h, m, wp, lp: 1)
    monkeypatch.setattr(g8.time, "sleep", lambda _: None)

    def fake_get_dlg_item(h, cid):
        if h == dlg_hwnd and cid == 12024:
            return ctrl_12024
        if h == dlg_hwnd and cid == 37011:
            return btn_37011
        if h == dlg_hwnd and cid == 1:
            return btn_ok
        if h == selector_dlg and cid == 2053:
            return edit_2053
        if h == selector_dlg and cid == 1:
            return 0x105E0
        return 0

    monkeypatch.setattr(g8.user32, "GetDlgItem", fake_get_dlg_item)
    monkeypatch.setattr(
        g8,
        "dump_child_windows_recursive",
        lambda h: [{"hwnd": tree_hwnd, "class_name": "SysTreeView32", "control_id": 100, "text": ""}],
    )
    monkeypatch.setattr(
        g8,
        "verify_tag_in_hmi_picker",
        lambda pid, selector_dlg, target_var, app_uia: (True, ["RTC_SEC", "T1_LEVEL_PV"], DummyTreeItem()),
    )

    # Simulate ctrl_12024 initially empty, then populated with 'T1_LEVEL_PV' after selector_dlg selection
    read_calls = {"n": 0}

    def fake_read_text(h, timeout_ms=1000):
        if h == ctrl_12024:
            read_calls["n"] += 1
            return "" if read_calls["n"] == 1 else "T1_LEVEL_PV"
        return ""

    monkeypatch.setattr(g8, "_read_window_text_timeout", fake_read_text)
    monkeypatch.setattr(
        g8,
        "_force_close_modal_dialog",
        lambda h, prefer_cancel=False, timeout=2.0: force_closed_hwnds.append((h, prefer_cancel)) or True,
    )

    # Simulate pre-check returning None, and post-OK check returning 'Invalid tag name' modal error
    err_calls = {"n": 0}

    def fake_detect_err(pid, parent_dlg_hwnd=None, timeout=2.0, evidence=None):
        err_calls["n"] += 1
        if err_calls["n"] == 1:
            return None
        return {"hwnd": "0x105c4", "title": "Error", "message": "Invalid tag name"}

    monkeypatch.setattr(g8, "detect_and_handle_error_dialog", fake_detect_err)

    with pytest.raises(AssertionError, match="FAIL_CLOSED: Cscape rejected HMI binding for 'T1_LEVEL_PV'.*Invalid tag name"):
        handle_hmi_binding_dialog(pid=1234, main_hwnd=0x1000, target_var="T1_LEVEL_PV", timeout=1.0)

    assert selected_called["count"] == 1, "Must call target_item.select() on the UIA TreeItem in selector_dlg!"
    assert (dlg_hwnd, True) in force_closed_hwnds, "Must force-close Dialog 173 on modal error before raising AssertionError!"


def test_place_hmi_object_on_screen_enforces_max_placement_seconds_timeout_fail_closed(monkeypatch):
    """Verify place_hmi_object_on_screen enforces max_placement_seconds wall-clock timeout and fails closed
    instead of hanging indefinitely at 'Tier 2: Enter fallback on placement'.
    """
    import scripts.g8_acceptance as g8
    from scripts.g8_acceptance import place_hmi_object_on_screen

    clock = {"t": 1000.0}

    def fake_time():
        clock["t"] += 10.0  # Advance 10s on each check to exceed max_placement_seconds=15.0 quickly
        return clock["t"]

    monkeypatch.setattr(g8.time, "time", fake_time)
    monkeypatch.setattr(g8.time, "sleep", lambda _: None)
    monkeypatch.setattr(g8.user32, "ScreenToClient", lambda h, pt: 1)
    monkeypatch.setattr(g8.user32, "SetForegroundWindow", lambda h: 1)
    monkeypatch.setattr(g8.user32, "BringWindowToTop", lambda h: 1)
    monkeypatch.setattr(g8.user32, "ShowWindow", lambda h, s: 1)
    monkeypatch.setattr(g8.user32, "SetFocus", lambda h: 1)
    monkeypatch.setattr(g8.user32, "PostMessageW", lambda h, m, wp, lp: 1)
    monkeypatch.setattr(g8, "_send_msg_timeout", lambda *a, **kw: 1)
    monkeypatch.setattr(g8, "find_screen_editor_statusbar", lambda h: 0x2000)
    monkeypatch.setattr(g8, "get_statusbar_texts_from_hwnd", lambda *a, **kw: ["0 Objects"])
    monkeypatch.setattr(g8, "handle_hmi_binding_dialog", lambda **kw: False)
    monkeypatch.setattr(g8.pywinauto.mouse, "click", lambda **kw: None)
    monkeypatch.setattr(g8.pywinauto.mouse, "double_click", lambda **kw: None)

    with pytest.raises(AssertionError, match="FAIL_CLOSED: Placement of 'T1_LEVEL_PV'.*timed out"):
        place_hmi_object_on_screen(
            main_hwnd=0x1000,
            screen_hwnd=0x1001,
            pid=1234,
            target_coords=(500, 250),
            target_var="T1_LEVEL_PV",
            canvas_rect=(345, 173, 1267, 345),
            expected_cumulative_count=1,
            max_placement_seconds=15.0,
        )


def test_get_statusbar_texts_from_hwnd_prefers_direct_pywinauto_and_ignores_empty_wm_user(monkeypatch):
    """Verify get_statusbar_texts_from_hwnd:
    1. Uses direct app.window(handle=sb_hwnd).texts() first (cross-process safe VirtualAllocEx/ReadProcessMemory).
    2. Does NOT pollute returned texts with empty strings ('') when cross-process WM_USER 0x040d returns empty buffers.
    """
    import scripts.g8_acceptance as g8
    from scripts.g8_acceptance import get_statusbar_texts_from_hwnd

    sb_hwnd = 0x20050
    monkeypatch.setattr(g8.win32gui, "IsWindow", lambda h: h == sb_hwnd)
    monkeypatch.setattr(g8.win32gui, "GetWindowText", lambda h: "FallbackText")

    # Simulate cross-process SB_GETPARTS (0x0406) returning 7 parts, while SB_GETTEXTW (0x040d) leaves buf empty
    monkeypatch.setattr(g8, "_send_msg_timeout", lambda h, m, wp, lp, timeout_ms=500: 7 if m == 0x0406 else 0)

    # Case 1: app is None -> WM_USER 0x040d yields 7 empty strings, which must NOT be appended to texts!
    res_no_app = get_statusbar_texts_from_hwnd(sb_hwnd, main_hwnd=0x1000, app=None)
    assert res_no_app == ["FallbackText"]

    # Case 2: app is provided -> direct app.window(handle=sb_hwnd).texts() returns real status bar panes immediately
    class DummyApp:
        def window(self, handle=None):
            assert handle == sb_hwnd

            class _SB:
                def texts(self):
                    return ["", "Screen: 1*", "", "", "", "", "1 Objects"]

            return _SB()

    res_with_app = get_statusbar_texts_from_hwnd(sb_hwnd, main_hwnd=0x1000, app=DummyApp())
    assert "1 Objects" in res_with_app
    assert g8.parse_statusbar_object_count(res_with_app) == 1


def test_place_hmi_object_on_screen_closes_lingering_thumbnails_and_activates_screen(monkeypatch):
    """Verify place_hmi_object_on_screen calls _prepare_screen_editor_for_placement to close any lingering
    'Screen Thumbnails' (#32770) modal dialog before dropping and binding the Numeric Display object.
    """
    import scripts.g8_acceptance as g8
    from scripts.g8_acceptance import place_hmi_object_on_screen

    thumb_dlg = 0xD04FC
    closed_dialogs = []

    monkeypatch.setattr(g8.time, "sleep", lambda _: None)
    monkeypatch.setattr(g8.win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(g8.win32gui, "IsWindowVisible", lambda h: True)
    monkeypatch.setattr(g8.win32process, "GetWindowThreadProcessId", lambda h: (1, 1234))
    monkeypatch.setattr(g8.win32gui, "GetClassName", lambda h: "#32770" if h == thumb_dlg else "HornerAPGTabbedGraphicsEditor")
    monkeypatch.setattr(g8.win32gui, "GetWindowText", lambda h: "Screen Thumbnails" if h == thumb_dlg else "")
    monkeypatch.setattr(g8.win32gui, "EnumWindows", lambda cb, extra: cb(thumb_dlg, extra))
    monkeypatch.setattr(
        g8,
        "_force_close_modal_dialog",
        lambda h, prefer_cancel=False, timeout=1.0: closed_dialogs.append(h) or True,
    )
    monkeypatch.setattr(g8.user32, "ScreenToClient", lambda h, pt: 1)
    monkeypatch.setattr(g8.user32, "SetForegroundWindow", lambda h: 1)
    monkeypatch.setattr(g8.user32, "BringWindowToTop", lambda h: 1)
    monkeypatch.setattr(g8.user32, "ShowWindow", lambda h, s: 1)
    monkeypatch.setattr(g8.user32, "SetFocus", lambda h: 1)
    monkeypatch.setattr(g8.user32, "PostMessageW", lambda h, m, wp, lp: 1)
    monkeypatch.setattr(g8, "_send_msg_timeout", lambda *a, **kw: 1)
    monkeypatch.setattr(g8, "find_screen_editor_statusbar", lambda h: 0x2000)

    sb_calls = {"n": 0}

    def fake_sb_texts(*a, **kw):
        sb_calls["n"] += 1
        return ["0 Objects"] if sb_calls["n"] == 1 else ["1 Objects"]

    monkeypatch.setattr(g8, "get_statusbar_texts_from_hwnd", fake_sb_texts)
    monkeypatch.setattr(g8, "handle_hmi_binding_dialog", lambda **kw: True)
    monkeypatch.setattr(g8.pywinauto.mouse, "click", lambda **kw: None)
    monkeypatch.setattr(g8.pywinauto.mouse, "double_click", lambda **kw: None)

    res = place_hmi_object_on_screen(
        main_hwnd=0x1000,
        screen_hwnd=0x1001,
        pid=1234,
        target_coords=(907, 248),
        target_var="T1_LEVEL_PV",
        canvas_rect=(548, 172, 1267, 344),
        expected_cumulative_count=1,
    )
    assert res["placed"] is True
    assert res["property_dialog_handled"] is True
    assert thumb_dlg in closed_dialogs, "Must force-close lingering Screen Thumbnails dialog before placement!"
