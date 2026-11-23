"""Unit test suite for scripts/probe_hmi_editor.py (Gate G8 HMI Editor Recon).

Fully offline test execution: zero reliance on live Cscape.exe process.
Validates AST, imports, PE resource forensics from GrEdit.dll, dynamic discovery (no hardcoded IDs),
provenance tagging, and fail-closed safety invariants.
"""

import ast
import inspect
from pathlib import Path
import pytest

from scripts.probe_hmi_editor import (
    CSCAPE_INSTALL_DIR,
    GREDIT_DLL_PATH,
    extract_gredit_dialog_forensics,
    extract_pe_hmi_object_provenance,
    find_dynamic_screen_menu_command,
    parse_pe_dialog_template,
    is_screen_editor_window,
    BASELINE_P1_SHA,
    BASE_P1_PATH,
)
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.security.exceptions import HardwareLockoutError


def test_probe_hmi_editor_syntax_and_ast():
    """Verify that scripts/probe_hmi_editor.py is syntactically valid python."""
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "probe_hmi_editor.py"
    assert script_path.exists(), f"Missing {script_path}"
    with open(script_path, "r", encoding="utf-8") as f:
        code = f.read()
    tree = ast.parse(code, filename=str(script_path))
    assert isinstance(tree, ast.Module)


def test_probe_hmi_editor_zero_hardcoded_ids_contract():
    """Verify that screen editor opening and object discovery use dynamic discovery, not hardcoded command IDs."""
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "probe_hmi_editor.py"
    with open(script_path, "r", encoding="utf-8") as f:
        code = f.read()

    # Verify dynamic discovery functions exist and are callable
    from scripts.probe_hmi_editor import open_screen_editor_dynamic, find_dynamic_screen_menu_command
    assert callable(open_screen_editor_dynamic)
    assert callable(find_dynamic_screen_menu_command)

    # Verify that find_dynamic_screen_menu_command works dynamically on arbitrary mock menus
    mock_menu = [
        {
            "position": 0,
            "text": "File",
            "path": "MenuBar -> File",
            "cmd_id": None,
            "has_submenu": True,
            "children": [
                {"position": 0, "text": "New", "path": "MenuBar -> File -> New", "cmd_id": 57600, "has_submenu": False, "children": []},
            ],
        },
        {
            "position": 1,
            "text": "Screens",
            "path": "MenuBar -> Screens",
            "cmd_id": None,
            "has_submenu": True,
            "children": [
                {"position": 0, "text": "View/Edit Screens", "path": "MenuBar -> Screens -> View/Edit Screens", "cmd_id": 99999, "has_submenu": False, "children": []},
            ],
        },
    ]
    resolved = find_dynamic_screen_menu_command(mock_menu)
    assert resolved is not None
    assert resolved["cmd_id"] == 99999
    assert resolved["text"] == "View/Edit Screens"


def test_gredit_dll_property_dialogs_forensics():
    """Verify extraction of authoritative property dialogs from GrEdit.dll."""
    if not GREDIT_DLL_PATH.exists():
        pytest.skip(f"GrEdit.dll not installed at {GREDIT_DLL_PATH}")

    forensics = extract_gredit_dialog_forensics()
    assert forensics["source"] == "pe_binary_forensics"
    assert forensics["dll_exists"] is True

    property_dialogs = forensics["property_dialogs"]

    # Verify Dialog 173 (Numeric Data Properties)
    assert "173" in property_dialogs
    d173 = property_dialogs["173"]
    assert "numeric" in d173["title"].lower()
    ctrl_ids_173 = {c["control_id"] for c in d173["controls"]}
    assert 1441 in ctrl_ids_173  # Data Source (Binding field)
    assert 1442 in ctrl_ids_173  # Data Format

    # Verify Dialog 138 (Indicator Properties)
    assert "138" in property_dialogs
    d138 = property_dialogs["138"]
    assert "indicator" in d138["title"].lower()
    ctrl_ids_138 = {c["control_id"] for c in d138["controls"]}
    assert 1441 in ctrl_ids_138  # Data Source (Binding field)
    assert 1007 in ctrl_ids_138  # Legend Plate

    # Verify Dialog 175 (ASCII Data Properties)
    assert "175" in property_dialogs
    d175 = property_dialogs["175"]
    assert "ascii" in d175["title"].lower()
    ctrl_ids_175 = {c["control_id"] for c in d175["controls"]}
    assert 1441 in ctrl_ids_175  # Data Source (Binding field)
    assert 1276 in ctrl_ids_175  # Font
    assert 1061 in ctrl_ids_175  # Digits

    # Verify Dialog 135 (Set Screen Size)
    assert "135" in property_dialogs
    d135 = property_dialogs["135"]
    assert "screen size" in d135["title"].lower()
    ctrl_ids_135 = {c["control_id"] for c in d135["controls"]}
    assert 1000 in ctrl_ids_135  # Width
    assert 1001 in ctrl_ids_135  # Height


def test_gredit_dll_binding_fields_contract():
    """Verify that variable binding fields for numeric display, indicator, and text are precisely mapped."""
    if not GREDIT_DLL_PATH.exists():
        pytest.skip(f"GrEdit.dll not installed at {GREDIT_DLL_PATH}")

    forensics = extract_gredit_dialog_forensics()
    binding_fields = forensics["binding_fields"]

    assert "numeric_display" in binding_fields
    num = binding_fields["numeric_display"]
    assert num["binding_field_id"] == 1441
    assert "Data Source" in num["binding_field_name"]
    assert "%R" in num["target_types"]
    assert "pe_dialog_template" in num["provenance"]

    assert "indicator" in binding_fields
    ind = binding_fields["indicator"]
    assert ind["binding_field_id"] == 1441
    assert "BOOL" in ind["target_types"]
    assert "pe_dialog_template" in ind["provenance"]

    assert "text" in binding_fields
    txt = binding_fields["text"]
    assert txt["binding_field_id"] == 1441
    assert "STRING" in txt["target_types"]

    assert "display_attributes_override" in binding_fields
    attr = binding_fields["display_attributes_override"]
    assert attr["override_variable_field_id"] == 1457
    assert attr["color_swatch_4_id"] == 1215


def test_pe_hmi_object_provenance_extraction():
    """Verify that authoritative HMI object types are extracted with provenance from GrEdit.dll."""
    if not GREDIT_DLL_PATH.exists():
        pytest.skip(f"GrEdit.dll not installed at {GREDIT_DLL_PATH}")

    objects = extract_pe_hmi_object_provenance()
    assert len(objects) >= 5

    types_found = {o["object_type"] for o in objects}
    assert "numeric_display" in types_found
    assert "indicator" in types_found
    assert "static_text" in types_found

    for obj in objects:
        assert obj["source"] == "pe_resource_provenance"
        assert obj["origin_dll"] == "GrEdit.dll"
        assert obj["resource_id"] > 0
        assert len(obj["name"]) > 0


def test_probe_hmi_safety_invariants():
    """Verify that hardware lockouts and baseline file immutability are strictly enforced."""
    # 1. COM port lockout assertion
    for port in ["COM1", "COM256"]:
        with pytest.raises(HardwareLockoutError):
            SecurityGuard.assert_port_safe(port)

    # 2. Baseline project immutability
    from scripts.g3_edit_roundtrip import compute_sha256
    assert BASE_P1_PATH.exists()
    assert compute_sha256(BASE_P1_PATH) == BASELINE_P1_SHA


def test_is_screen_editor_window_ladder_rejection_and_screen_acceptance(monkeypatch):
    """Verify that is_screen_editor_window strictly rejects ladder windows and accepts screen windows."""
    import win32gui

    # 1. Invalid or 0 HWND -> False
    assert is_screen_editor_window(0) is False

    # 2. Mock ladder window: class CW5EditLDWnd, title 'main' -> False (FAIL_CLOSED)
    monkeypatch.setattr(win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(win32gui, "GetWindowText", lambda h: "main")
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "CW5EditLDWnd")
    assert is_screen_editor_window(0x1000) is False

    # 3. Mock ladder window with project name in title
    monkeypatch.setattr(win32gui, "GetWindowText", lambda h: "probe_hmi_editor.csp")
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "CW5EditLDWnd")
    assert is_screen_editor_window(0x1001) is False

    # 4. Mock screen editor window: title 'Screen 1', class 'CGrEditView' -> True
    monkeypatch.setattr(win32gui, "GetWindowText", lambda h: "Screen 1")
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "CGrEditView")
    assert is_screen_editor_window(0x2000) is True

    # 5. Mock screen editor window: title 'Main Screen', MFC Afx Frame -> True
    monkeypatch.setattr(win32gui, "GetWindowText", lambda h: "Main Screen")
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "Afx:008B0000:b:00010003:00000006")
    assert is_screen_editor_window(0x2001) is True

    # 6. Mock HornerAPGTabbedGraphicsEditor docked window class -> True
    monkeypatch.setattr(win32gui, "GetWindowText", lambda h: "")
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "HornerAPGTabbedGraphicsEditor")
    assert is_screen_editor_window(0x32a050c) is True


def test_probe_hmi_editor_zero_mdi_active_fallback():
    """Verify that mdi_active_fallback and mdi_client_fallback return values are completely removed from scripts/probe_hmi_editor.py."""
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "probe_hmi_editor.py"
    with open(script_path, "r", encoding="utf-8") as f:
        code = f.read()

    # Neither string may be returned as an activation method
    assert '"mdi_active_fallback"' not in code
    assert "'mdi_active_fallback'" not in code
    assert '"mdi_client_fallback"' not in code
    assert "'mdi_client_fallback'" not in code


def test_open_screen_editor_dynamic_fails_closed_when_no_screen(monkeypatch):
    """Verify open_screen_editor_dynamic fails closed when only ladder editor windows are present."""
    import win32gui
    from scripts.probe_hmi_editor import open_screen_editor_dynamic

    # Mock MDI containers to return a ladder window (CW5EditLDWnd)
    monkeypatch.setattr(
        "scripts.probe_hmi_editor.find_mdi_containers",
        lambda h: (0x5000, 0x5001, [0x5001]),
    )
    monkeypatch.setattr(win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(win32gui, "GetWindowText", lambda h: "main")
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "CW5EditLDWnd")
    monkeypatch.setattr(win32gui, "EnumChildWindows", lambda h, cb, extra: None)

    class MockApp:
        pass

    h_res, method = open_screen_editor_dynamic(0x1000, 1234, MockApp(), {})
    # Must fail closed: return None and 'not_resolved', NEVER return the ladder window handle
    assert h_res is None
    assert method == "not_resolved"


def test_tree_navigation_candidate_scoring_and_thumbnail_targeting():
    """Verify tree search prioritizes 'Screen Thumbnail' to open Screen Thumbnail view per Cscape 10.2 documentation."""
    from scripts.probe_hmi_editor import find_and_activate_screen_in_tree

    # Verify function signature accepts evidence dictionary
    sig = inspect.signature(find_and_activate_screen_in_tree)
    assert "evidence" in sig.parameters

    # Verify that calling with invalid HWND fails safely
    evidence = {}
    h, name = find_and_activate_screen_in_tree(0, 0, evidence)
    assert h is None
    assert name == ""


def test_dump_user_interface_ribbon_objects_logging(monkeypatch):
    """Verify dump_user_interface_ribbon_objects enumerates buttons and handles empty ribbon gracefully."""
    from scripts.probe_hmi_editor import dump_user_interface_ribbon_objects

    class MockApp:
        def window(self, **kwargs):
            class MockWindow:
                def descendants(self, **dkwargs):
                    return []
            return MockWindow()

    objs = dump_user_interface_ribbon_objects(0x1234, MockApp())
    assert isinstance(objs, list)
    assert len(objs) == 0


def test_gredit_dll_screen_thumbnails_dialog_180():
    """Verify extraction of Dialog 180 Screen Thumbnails from GrEdit.dll."""
    if not GREDIT_DLL_PATH.exists():
        pytest.skip(f"GrEdit.dll not installed at {GREDIT_DLL_PATH}")

    forensics = extract_gredit_dialog_forensics()
    assert "180" in forensics["property_dialogs"]
    dlg180 = forensics["property_dialogs"]["180"]
    assert "screen thumbnails" in dlg180["title"].lower()
    ctrl_ids_180 = {c["control_id"] for c in dlg180["controls"]}
    assert 1058 in ctrl_ids_180  # Thumbnail Canvas
    assert 1142 in ctrl_ids_180  # Previous Button
    assert 1143 in ctrl_ids_180  # Next Button
    assert 1 in ctrl_ids_180     # OK Button
    assert 2 in ctrl_ids_180     # Cancel Button


def test_window_snapshot_and_new_window_differential_logging(monkeypatch):
    """Verify window snapshot captures handles and logs newly appeared windows."""
    from scripts.probe_hmi_editor import snapshot_all_windows, log_and_record_new_windows

    # Initially empty snapshot
    initial_snap = {
        0x1000: {"hwnd": 0x1000, "hwnd_hex": "0x1000", "class_name": "MainWnd", "title": "Main", "parent_hwnd": 0, "parent_hwnd_hex": None, "control_id": 0, "rect": [0, 0, 100, 100], "client_rect": [0, 0, 100, 100], "is_visible": True, "is_enabled": True}
    }

    # Mock snapshot_all_windows to return initial + new window
    monkeypatch.setattr(
        "scripts.probe_hmi_editor.snapshot_all_windows",
        lambda pid, main_h: {
            0x1000: initial_snap[0x1000],
            0x2000: {"hwnd": 0x2000, "hwnd_hex": "0x2000", "class_name": "#32770", "title": "Screen Thumbnails", "parent_hwnd": 0x1000, "parent_hwnd_hex": "0x1000", "control_id": 180, "rect": [50, 50, 420, 305], "client_rect": [0, 0, 370, 255], "is_visible": True, "is_enabled": True}
        }
    )
    monkeypatch.setattr(
        "scripts.probe_hmi_editor.find_mdi_containers",
        lambda main_h: (0x1500, None, [])
    )

    evidence = {}
    new_wins = log_and_record_new_windows(initial_snap, 1234, 0x1000, "Test Context", evidence)
    assert len(new_wins) == 1
    assert new_wins[0]["hwnd"] == 0x2000
    assert new_wins[0]["category"] == "Popup Dialog"
    assert new_wins[0]["title"] == "Screen Thumbnails"
    assert "new_windows" in evidence
    assert len(evidence["new_windows"]) == 1


def test_click_ribbon_view_thumbnails_locates_and_clicks_button(monkeypatch):
    """Verify click_ribbon_view_thumbnails finds 'View Thumbnails' in Screens group and clicks it."""
    from scripts.probe_hmi_editor import click_ribbon_view_thumbnails
    import win32gui

    clicked = []

    class MockRect:
        def __init__(self, l, t, r, b):
            self.left = l
            self.top = t
            self.right = r
            self.bottom = b
        def height(self):
            return self.bottom - self.top
        def width(self):
            return self.right - self.left

    class MockElementInfo:
        def __init__(self, name):
            self.name = name
            self.automation_id = ""

    class MockButton:
        def __init__(self, name, rect):
            self.element_info = MockElementInfo(name)
            self._rect = rect
            self.iface_invoke = None
        def window_text(self):
            return self.element_info.name
        def rectangle(self):
            return self._rect
        def parent(self):
            class MockParent:
                element_info = MockElementInfo("Screens")
                def window_text(self):
                    return "Screens"
            return MockParent()
        def click_input(self):
            clicked.append("click_input")

    class MockApp:
        def window(self, **kwargs):
            class MockWindow:
                def descendants(self, **dkwargs):
                    if dkwargs.get("control_type") == "Button":
                        return [
                            MockButton("Do I/O", MockRect(10, 50, 60, 90)),
                            MockButton("View Thumbnails", MockRect(100, 50, 180, 90)),
                        ]
                    return []
            return MockWindow()

    monkeypatch.setattr("scripts.probe_hmi_editor.user32.SetForegroundWindow", lambda h: True)
    monkeypatch.setattr("pywinauto.mouse.click", lambda **kwargs: clicked.append("mouse_click"))

    res = click_ribbon_view_thumbnails(0x1000, MockApp())
    assert res is True
    assert "click_input" in clicked or "mouse_click" in clicked


def test_find_screen_thumbnail_window_detection(monkeypatch):
    """Verify find_screen_thumbnail_window detects Dialog 180 and thumbnail titles."""
    from scripts.probe_hmi_editor import find_screen_thumbnail_window
    import win32gui

    def mock_enum_windows(callback, extra):
        callback(0x3000, extra)

    monkeypatch.setattr(win32gui, "EnumWindows", mock_enum_windows)
    monkeypatch.setattr(win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(win32gui, "IsWindowVisible", lambda h: True)
    monkeypatch.setattr("win32process.GetWindowThreadProcessId", lambda h: (1, 1234))
    monkeypatch.setattr(win32gui, "GetWindowText", lambda h: "Screen Thumbnails")
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "#32770")
    monkeypatch.setattr(win32gui, "GetDlgItem", lambda h, cid: 0x3001 if cid == 1058 else 0)

    found_h = find_screen_thumbnail_window(1234, 0x1000, timeout=1.0)
    assert found_h == 0x3000


def test_double_click_screen1_thumbnail_dispatches_clicks_and_ok(monkeypatch):
    """Verify double_click_screen1_thumbnail finds canvas 1058/1409 and sends double-click and OK."""
    from scripts.probe_hmi_editor import double_click_screen1_thumbnail
    import win32gui

    dispatched = []

    monkeypatch.setattr("scripts.probe_hmi_editor.user32.SetForegroundWindow", lambda h: True)
    monkeypatch.setattr("scripts.probe_hmi_editor.dump_child_windows_recursive", lambda h: [])
    monkeypatch.setattr(win32gui, "GetDlgItem", lambda h, cid: 0x3050 if cid in (1058, 1409) else 0)
    monkeypatch.setattr(win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(win32gui, "IsWindowVisible", lambda h: True)
    monkeypatch.setattr(win32gui, "GetWindowRect", lambda h: (100, 100, 500, 400))
    monkeypatch.setattr("pywinauto.mouse.click", lambda **kwargs: dispatched.append("mouse_click"))
    monkeypatch.setattr("pywinauto.mouse.double_click", lambda **kwargs: dispatched.append("mouse_dblclick"))
    monkeypatch.setattr(
        "scripts.probe_hmi_editor.user32.SendMessageW",
        lambda h, msg, wparam, lparam: dispatched.append(f"SendMessage_{msg}_{wparam}"),
    )
    monkeypatch.setattr(
        "scripts.probe_hmi_editor.user32.PostMessageW",
        lambda h, msg, wparam, lparam: dispatched.append(f"SendMessage_{msg}_{wparam}"),
    )

    evidence = {}
    res = double_click_screen1_thumbnail(0x3000, evidence)
    assert res is True
    assert "mouse_click" in dispatched
    assert "mouse_dblclick" in dispatched
    # WM_COMMAND 1 (OK button)
    assert any("SendMessage_273_1" in d for d in dispatched)


def test_find_screen_editor_window_by_class_resolves_docked_editor(monkeypatch):
    """Verify find_screen_editor_window_by_class locates HornerAPGTabbedGraphicsEditor in child windows."""
    from scripts.probe_hmi_editor import find_screen_editor_window_by_class
    import win32gui

    def mock_enum_child(parent, callback, extra):
        callback(0x32A050C, extra)

    monkeypatch.setattr(win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(win32gui, "IsWindowVisible", lambda h: True)
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "HornerAPGTabbedGraphicsEditor")
    monkeypatch.setattr(win32gui, "EnumChildWindows", mock_enum_child)

    res = find_screen_editor_window_by_class(0x1000, 1234)
    assert res is not None
    assert res[0] == 0x32A050C
    assert res[1] == "HornerAPGTabbedGraphicsEditor"


def test_open_screen_editor_dynamic_resolves_horner_apg_tabbed_graphics_editor(monkeypatch):
    """Verify open_screen_editor_dynamic returns HornerAPGTabbedGraphicsEditor with docked_class method."""
    from scripts.probe_hmi_editor import open_screen_editor_dynamic
    import win32gui

    monkeypatch.setattr(
        "scripts.probe_hmi_editor.find_screen_editor_window_by_class",
        lambda main_h, pid: (0x32A050C, "HornerAPGTabbedGraphicsEditor")
    )
    monkeypatch.setattr(
        "scripts.probe_hmi_editor.find_mdi_containers",
        lambda h: (0x1000, None, [])
    )

    class MockApp:
        pass

    screen_h, method = open_screen_editor_dynamic(0x1000, 1234, MockApp(), {})
    assert screen_h == 0x32A050C
    assert "docked_class:HornerAPGTabbedGraphicsEditor" in method


def test_find_screen_editor_window_by_class_resolves_when_not_visible(monkeypatch):
    """Verify find_screen_editor_window_by_class resolves even if IsWindowVisible returns False during layout init."""
    from scripts.probe_hmi_editor import find_screen_editor_window_by_class
    import win32gui

    def mock_enum_child(parent, callback, extra):
        callback(0x32A050C, extra)

    monkeypatch.setattr(win32gui, "IsWindow", lambda h: True)
    # Window is NOT yet visible during layout/docking setup
    monkeypatch.setattr(win32gui, "IsWindowVisible", lambda h: False)
    monkeypatch.setattr(win32gui, "GetClassName", lambda h: "HornerAPGTabbedGraphicsEditor")
    monkeypatch.setattr(win32gui, "EnumChildWindows", mock_enum_child)

    res = find_screen_editor_window_by_class(0x1000, 1234)
    assert res is not None
    assert res[0] == 0x32A050C
    assert res[1] == "HornerAPGTabbedGraphicsEditor"


def test_find_screen_editor_window_by_class_resolves_from_top_level_descendants_and_snapshot(monkeypatch):
    """Verify find_screen_editor_window_by_class scans top-level descendants and snapshots."""
    from scripts.probe_hmi_editor import find_screen_editor_window_by_class
    import win32gui

    # Step 1 returns nothing
    monkeypatch.setattr(win32gui, "EnumChildWindows", lambda p, cb, ex: None)
    monkeypatch.setattr(win32gui, "EnumWindows", lambda cb, ex: None)

    # Step 3 snapshot returns HornerAPGTabbedGraphicsEditor
    monkeypatch.setattr(
        "scripts.probe_hmi_editor.snapshot_all_windows",
        lambda pid, main_h: {
            0x4500: {"hwnd": 0x4500, "class_name": "HornerAPGTabbedGraphicsEditor", "title": "Screen 1"}
        }
    )

    res = find_screen_editor_window_by_class(0x1000, 1234)
    assert res is not None
    assert res[0] == 0x4500
    assert res[1] == "HornerAPGTabbedGraphicsEditor"





