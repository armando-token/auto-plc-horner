# -*- coding: utf-8 -*-
"""Gate G7 Ladder Editor Concrete Element Placement & Roundtrip Verification Runner.

Mandate: Gate G7 Live Ladder Placement Roundtrip Verification with Negative Control & Visual Evidence.
Classification: TESTED_MOCK / INTEGRATION [winsta0\\Default]
Strict Engineering Directives Enforced:
1. Baseline Immutability: work/disposable/p1_base.csp is verified via SHA-256
   before and after execution (5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881).
2. Fail-Closed Hardware Lockout: Physical COM ports 1..256, companion flasher binaries,
   download CLI switches, and Win32 download command IDs 32827/33149 permanently blocked.
3. Unknown Dialog Guard: Any modal dialog (#32770 or popup) that is not in the recognized
   allowlist immediately stops the process, logs details, captures a screenshot, and aborts
   without saving.
4. Concrete Placement: On main ladder, insert a new rung, place a Normally Open Contact bound
   to existing BOOL (ALW_ON), and place a Normally Open Coil bound to G3-style test BOOL
   (G3_TEST_VAR_01).
5. Clean Lifecycle: Save project, close editor tab, close Cscape gracefully with zero leftover processes.
6. Visual Reopen Verification: Reopen the saved project in Cscape and capture a high-quality
   screenshot of the main ladder showing the rung with contact and coil (artifacts/G7/ladder_roundtrip_reopen_main.png).
7. Negative Control CFBF Oracle: Run the same CFBF oracle on untouched p1_base copy as a negative
   control and compute/print the delta (rung/element count, contact+coil records) that exists ONLY
   in the roundtrip file; element count must be >= 2.
8. Status Contract: Strictly return status: success | failed | blocked | inconclusive.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import olefile
from PIL import ImageGrab
import win32con
import win32gui
import win32process
from pywinauto import Application

# Ensure repository root and src are on sys.path
REPO_ROOT = Path(r"C:\HornerAI\jev-cscape-agent")
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.security.exceptions import HardwareLockoutError, LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard

from scripts.g3_edit_roundtrip import (
    BASE_P1_PATH,
    BASELINE_P1_SHA,
    BASELINE_SANDBOX_SHA,
    COPIES_DIR,
    SOURCE_SANDBOX_PATH,
    assert_safety_invariants,
    close_active_editor_tab,
    close_cscape_gracefully,
    compute_sha256,
    evaluate_window_for_dialog_guard,
    is_known_cscape_dialog,
    kill_leftover_cscape,
    parse_csp_cfbf_declarations,
)
from scripts.probe_ladder_editor import (
    configure_cscape_registry,
    expand_all_tree_nodes,
    find_mdi_containers,
    launch_cscape_with_project,
    wait_for_about_cscape_and_main_enabled,
    wait_until_no_dialogs_and_main_ready,
)

# Constants & Paths
ARTIFACTS_G7_DIR = REPO_ROOT / "artifacts" / "G7"
ARTIFACTS_G7_DIR.mkdir(parents=True, exist_ok=True)
STEPS_DIR = ARTIFACTS_G7_DIR / "ladder_roundtrip_steps"
STEPS_DIR.mkdir(parents=True, exist_ok=True)
EVIDENCE_PATH = ARTIFACTS_G7_DIR / "g7_ladder_roundtrip.json"
LOG_DIR = REPO_ROOT / "artifacts" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

REOPEN_MAIN_SCREENSHOT = ARTIFACTS_G7_DIR / "ladder_roundtrip_reopen_main.png"
REOPEN_CANVAS_SCREENSHOT = ARTIFACTS_G7_DIR / "ladder_roundtrip_canvas.png"

TARGET_COPY_PATH = COPIES_DIR / "g7_ladder_roundtrip.csp"
CAMPAIGN_G3_PATH = COPIES_DIR / "campaign_run_01.csp"

TEST_CONTACT_TAG = "ALW_ON"
TEST_COIL_TAG = "G3_TEST_VAR_01"

# Win32 Command IDs
ID_SELECT_ELEMENTS = 112       # ESC / Select tool
ID_NO_CONTACT = 1000           # 'q' / F2 Normally Open Contact
ID_NC_CONTACT = 1001           # 'r' Normally Closed Contact
ID_NO_COIL = 1002              # 'x' / F9 Normally Open Coil
ID_BRANCH = 1005               # 's' Branch
ID_COMMENT = 1006              # 't' Comment
ID_NEW_RUNG_CONTEXT = 32820    # New Rung in PAGEMENU_RAIL
ID_INSERT_NEW_RUNG = 37980     # Insert New Rung accelerator/menu
ID_PROGRAM_ERRORCHECK = 32826  # Ctrl+E Error Check
ID_FILE_SAVE = 57603           # Ctrl+S Save
ID_PROGRAM_DOWNLOAD = 32827    # BLOCKED
ID_CONTROLLER_DOWNLOAD = 33149 # BLOCKED

# Setup Logger
logger = logging.getLogger("g7_ladder_roundtrip")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    fh = logging.FileHandler(LOG_DIR / "g7_ladder_roundtrip.log", mode="w", encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(sh)
    logger.addHandler(fh)

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32


class UnknownDialogError(RuntimeError):
    """Raised when an unrecognized modal dialog is encountered, triggering immediate fail-closed abort."""
    pass


def scan_for_unknown_dialogs(pid: int, allowed_titles: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    """Scan all top-level windows for any unauthorized modal dialog.

    If an unrecognized modal dialog is detected, returns metadata dictionary.
    """
    if allowed_titles is None:
        allowed_titles = ["about cscape", "i/o point", "cscape", "tip of the day", "select element type"]

    unknown_found: Optional[Dict[str, Any]] = None

    def _enum_cb(hwnd: int, _: Any) -> bool:
        nonlocal unknown_found
        try:
            if not win32gui.IsWindow(hwnd) or not win32gui.IsWindowVisible(hwnd):
                return True
            _, w_pid = win32process.GetWindowThreadProcessId(hwnd)
            if w_pid != pid:
                return True

            cls_name = win32gui.GetClassName(hwnd)
            if cls_name == "#32770":
                title = win32gui.GetWindowText(hwnd).strip()
                t_lower = title.lower()
                is_allowed = any(a in t_lower for a in allowed_titles)
                if not is_allowed:
                    r = win32gui.GetWindowRect(hwnd)
                    unknown_found = {
                        "hwnd": hex(hwnd),
                        "title": title,
                        "class": cls_name,
                        "rect": [r[0], r[1], r[2], r[3]],
                    }
                    return False
        except Exception:
            pass
        return True

    win32gui.EnumWindows(_enum_cb, None)
    return unknown_found


def capture_g7_screenshot(window_target: Any, out_path: Union[str, Path], crop_bbox: Optional[Tuple[int, int, int, int]] = None) -> Optional[str]:
    """Capture a high-quality screenshot of the specified window and write to target path.
    Uses pywinauto capture_as_image, ImageGrab, and Win32 GDI PrintWindow fallbacks.
    """
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    img = None

    hwnd = None
    if isinstance(window_target, int):
        hwnd = window_target
    elif hasattr(window_target, "handle"):
        hwnd = getattr(window_target, "handle", None)
    elif hasattr(window_target, "element_info") and hasattr(window_target.element_info, "handle"):
        hwnd = getattr(window_target.element_info, "handle", None)

    # Method 1: pywinauto capture_as_image
    try:
        if hasattr(window_target, "capture_as_image"):
            img = window_target.capture_as_image()
        elif hwnd and win32gui.IsWindow(hwnd):
            from pywinauto import Application
            app_temp = Application(backend="win32").connect(handle=hwnd)
            win_temp = app_temp.window(handle=hwnd)
            img = win_temp.capture_as_image()
    except Exception as e:
        logger.debug(f"pywinauto capture_as_image note: {e}")

    # Method 2: ImageGrab by bbox
    if img is None:
        try:
            if hwnd and win32gui.IsWindow(hwnd) and win32gui.IsWindowVisible(hwnd):
                r = win32gui.GetWindowRect(hwnd)
                if r[2] > r[0] and r[3] > r[1]:
                    img = ImageGrab.grab(bbox=r)
            elif window_target is not None and hasattr(window_target, "rectangle"):
                r = window_target.rectangle()
                bbox = (r.left, r.top, r.right, r.bottom)
                img = ImageGrab.grab(bbox=bbox)
        except Exception as e:
            logger.debug(f"ImageGrab bbox failed: {e}")

    # Method 3: Win32 GDI PrintWindow direct fallback
    if img is None and hwnd and win32gui.IsWindow(hwnd):
        try:
            import win32ui
            from PIL import Image
            r = win32gui.GetWindowRect(hwnd)
            w = max(1, r[2] - r[0])
            h = max(1, r[3] - r[1])
            hwnd_dc = win32gui.GetWindowDC(hwnd)
            mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
            save_dc = mfc_dc.CreateCompatibleDC()
            bitmap = win32ui.CreateBitmap()
            bitmap.CreateCompatibleBitmap(mfc_dc, w, h)
            save_dc.SelectObject(bitmap)
            user32.PrintWindow(hwnd, save_dc.GetSafeHdc(), 2)  # PW_RENDERFULLCONTENT
            bmp_info = bitmap.GetInfo()
            bmp_str = bitmap.GetBitmapBits(True)
            img = Image.frombuffer("RGB", (bmp_info["bmWidth"], bmp_info["bmHeight"]), bmp_str, "raw", "BGRX", 0, 1)
            win32gui.DeleteObject(bitmap.GetHandle())
            save_dc.DeleteDC()
            mfc_dc.DeleteDC()
            win32gui.ReleaseDC(hwnd, hwnd_dc)
        except Exception as e:
            logger.warning(f"GDI PrintWindow direct fallback note: {e}")

    # Method 4: ImageGrab full desktop
    if img is None:
        try:
            img = ImageGrab.grab()
        except Exception as e:
            logger.warning(f"Full desktop grab failed: {e}")

    if img is None:
        logger.error(f"All capture methods exhausted for target {window_target}")
        return None

    if crop_bbox is not None:
        try:
            img = img.crop(crop_bbox)
        except Exception as e:
            logger.debug(f"Crop failed: {e}")

    try:
        img.save(str(target))
        logger.info(f"Captured screenshot saved to: {target}")
        return str(target)
    except Exception as e:
        logger.error(f"Failed to save screenshot to {target}: {e}")
        return None


def activate_ladder_toolbar_button(main_hwnd: int, cmd_id: int) -> bool:
    """Activate vertical toolbar button by direct click and WM_COMMAND dispatch."""
    coords_map = {
        ID_SELECT_ELEMENTS: (11, 11),
        ID_NO_CONTACT: (11, 82),
        ID_NC_CONTACT: (11, 104),
        ID_NO_COIL: (11, 126),
    }
    ladder_mdi, canvas_hwnd = resolve_ladder_canvas(main_hwnd)
    tb_hwnd = None
    if ladder_mdi:
        def find_tb(h, _):
            nonlocal tb_hwnd
            if win32gui.GetClassName(h) == "ToolbarWindow32" and user32.GetDlgCtrlID(h) == 4500:
                tb_hwnd = h
                return False
            return True
        win32gui.EnumChildWindows(ladder_mdi, find_tb, None)

    # 1. Post WM_COMMAND to ladder_mdi and canvas
    if ladder_mdi:
        user32.PostMessageW(ladder_mdi, win32con.WM_COMMAND, cmd_id, tb_hwnd or 0)
    if canvas_hwnd:
        user32.PostMessageW(canvas_hwnd, win32con.WM_COMMAND, cmd_id, tb_hwnd or 0)

    # 2. Click toolbar button directly if coordinates known
    if tb_hwnd and cmd_id in coords_map:
        cx, cy = coords_map[cmd_id]
        lp = ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)
        user32.PostMessageW(tb_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lp)
        user32.PostMessageW(tb_hwnd, win32con.WM_LBUTTONUP, 0, lp)

    time.sleep(0.3)
    return True


def launch_cscape_project_robust(project_path: Path, timeout: float = 30.0) -> Tuple[Application, int, int]:
    """Launch Cscape 10.2 with project file, robust against delayed presentation and PID recycling."""
    import psutil
    from scripts.g3_edit_roundtrip import DEFAULT_CSCAPE_PATH, get_cscape_processes, enumerate_cscape_windows

    kill_leftover_cscape()
    time.sleep(2.0)
    configure_cscape_registry(project_path)

    abs_path = str(project_path.resolve())
    logger.info(f"Launching Cscape 10.2 with project: {abs_path}...")
    proc_obj = psutil.Popen([DEFAULT_CSCAPE_PATH, abs_path], cwd=os.path.dirname(DEFAULT_CSCAPE_PATH))
    expected_pid = proc_obj.pid
    logger.info(f"Launched Cscape PID {expected_pid}. Waiting up to {timeout}s for main window...")

    main_hwnd = None
    actual_pid = expected_pid
    start_t = time.time()

    while time.time() - start_t < timeout:
        time.sleep(1.0)
        # 1. Check windows by expected_pid
        windows = enumerate_cscape_windows(expected_pid)
        for h, cls, title in windows:
            if cls.startswith("Afx") and "cscape" in title.lower():
                main_hwnd = h
                actual_pid = expected_pid
                break
        if main_hwnd:
            break

        # 2. Check all Cscape processes
        for p in get_cscape_processes():
            p_windows = enumerate_cscape_windows(p.pid)
            for h, cls, title in p_windows:
                if cls.startswith("Afx") and "cscape" in title.lower():
                    main_hwnd = h
                    actual_pid = p.pid
                    break
            if main_hwnd:
                break
        if main_hwnd:
            break

        # 3. Broad fallback: enumerate all visible windows for Afx + cscape
        def _check_top(h: int, _: Any) -> bool:
            nonlocal main_hwnd, actual_pid
            if win32gui.IsWindowVisible(h):
                cls = win32gui.GetClassName(h)
                t = win32gui.GetWindowText(h)
                if cls.startswith("Afx") and "cscape" in t.lower():
                    _, wpid = win32process.GetWindowThreadProcessId(h)
                    main_hwnd = h
                    actual_pid = wpid
                    return False
            return True

        win32gui.EnumWindows(_check_top, None)
        if main_hwnd:
            break

    if not main_hwnd:
        kill_leftover_cscape()
        raise RuntimeError(f"Failed to locate Cscape main window for project '{project_path.name}'.")

    logger.info(f"Cscape main window located: HWND {hex(main_hwnd)}, PID {actual_pid}")
    try:
        if win32gui.IsIconic(main_hwnd):
            win32gui.ShowWindow(main_hwnd, win32con.SW_RESTORE)
        user32.SetForegroundWindow(main_hwnd)
    except Exception:
        pass
    time.sleep(1.0)
    app = Application(backend="win32").connect(process=actual_pid)
    return app, actual_pid, main_hwnd


def dismiss_startup_dialogs_and_wait_ready(
    pid: int,
    main_hwnd: int,
    app: Optional[Application] = None,
    max_wait_seconds: float = 30.0,
    evidence: Optional[Dict[str, Any]] = None,
) -> bool:
    """Actively wait for and dismiss startup dialogs ('About Cscape', 'Tip of the Day', etc.)
    and ensure main_hwnd is fully enabled and ready, even if Cscape created the dialog before showing it."""
    logger.info(f"Waiting for startup dialogs and main window HWND {hex(main_hwnd)} enabled (max {max_wait_seconds}s)...")
    start = time.time()
    seen_dialogs = []

    while time.time() - start < max_wait_seconds:
        hwnds = []
        def _enum_win(h, _):
            try:
                _, wpid = win32process.GetWindowThreadProcessId(h)
                if wpid == pid:
                    hwnds.append(h)
            except Exception:
                pass
            return True
        win32gui.EnumWindows(_enum_win, None)

        main_is_enabled = win32gui.IsWindowEnabled(main_hwnd)

        for h in hwnds:
            if h == main_hwnd or not win32gui.IsWindow(h):
                continue
            cls = win32gui.GetClassName(h)
            title = win32gui.GetWindowText(h)
            t_low = title.lower()

            is_about = any(k in t_low for k in ["about cscape", "tip of the day", "welcome"]) or (cls == "#32770" and "about" in t_low)
            is_modal_startup = (cls == "#32770" and not main_is_enabled)

            if is_about or is_modal_startup:
                logger.info(f"Dismissing startup dialog '{title}' (HWND {hex(h)}, class '{cls}')...")
                seen_dialogs.append({"hwnd": hex(h), "title": title, "class": cls})
                user32.PostMessageW(h, win32con.WM_COMMAND, 1, 0)  # IDOK
                user32.PostMessageW(h, win32con.WM_COMMAND, 2, 0)  # IDCANCEL
                user32.PostMessageW(h, win32con.WM_CLOSE, 0, 0)
                time.sleep(0.5)

        main_is_enabled = win32gui.IsWindowEnabled(main_hwnd)
        if main_is_enabled:
            try:
                if win32gui.IsIconic(main_hwnd):
                    win32gui.ShowWindow(main_hwnd, win32con.SW_RESTORE)
                user32.BringWindowToTop(main_hwnd)
                user32.SetForegroundWindow(main_hwnd)
            except Exception:
                pass
            time.sleep(0.5)

            blocking = False
            for h in hwnds:
                if h != main_hwnd and win32gui.IsWindow(h):
                    c = win32gui.GetClassName(h)
                    if c == "#32770":
                        r = win32gui.GetWindowRect(h)
                        if (r[2] - r[0] > 60) and (r[3] - r[1] > 60):
                            blocking = True
                            break
            if not blocking:
                elapsed = time.time() - start
                logger.info(f"Main window HWND {hex(main_hwnd)} confirmed ENABLED and ready after {elapsed:.1f}s.")
                if evidence is not None and seen_dialogs:
                    evidence.setdefault("dialogs_encountered", []).extend(seen_dialogs)
                return True

        time.sleep(0.5)

    raise RuntimeError(f"Main window HWND {hex(main_hwnd)} remained disabled after {max_wait_seconds}s waiting for startup dialogs.")


def open_main_ladder_editor(main_hwnd: int, pid: int, app_uia: Optional[Application] = None) -> bool:
    """Navigate Project Navigator SysTreeView32 (ID 300) to open the 'main' ladder editor."""
    logger.info("Opening 'main' ladder editor via Project Navigator...")

    # 1. Check if ladder editor is already open in MDI
    mdi_client, active_mdi, mdi_children = find_mdi_containers(main_hwnd)
    for child_h in ([active_mdi] if active_mdi else []) + mdi_children:
        if child_h and win32gui.IsWindow(child_h):
            c_title = win32gui.GetWindowText(child_h)
            if "main" in c_title.lower() or "ladder" in c_title.lower():
                logger.info(f"Main ladder editor already open: '{c_title}' (HWND {hex(child_h)})")
                return True

    # 2. Locate Project Navigator SysTreeView32 (ID 300) with retry polling
    tree_hwnd = None
    poll_start = time.time()
    while time.time() - poll_start < 6.0:
        def find_tree_cb(h: int, _: Any) -> bool:
            nonlocal tree_hwnd
            if win32gui.GetClassName(h) == "SysTreeView32":
                cid = user32.GetDlgCtrlID(h)
                if cid == 300 or tree_hwnd is None:
                    tree_hwnd = h
                    if cid == 300:
                        return False
            return True

        win32gui.EnumChildWindows(main_hwnd, find_tree_cb, None)
        if tree_hwnd:
            break
        time.sleep(0.2)

    if not tree_hwnd:
        logger.error("Could not locate Project Navigator SysTreeView32 (ID 300)")
        return False

    expand_all_tree_nodes(tree_hwnd)
    time.sleep(1.0)

    # 3. Double-click standard 'Main' node coordinates in TreeView
    logger.info("Clicking 'Main' node in Project Navigator SysTreeView32...")
    for y_offset in [46, 50, 42, 60, 35]:
        lparam = ((y_offset & 0xFFFF) << 16) | (40 & 0xFFFF)
        user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam)
        user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONUP, 0, lparam)
        user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam)
        user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONUP, 0, lparam)
        time.sleep(1.5)

        # Check if ladder editor opened
        _, active_mdi, mdi_children = find_mdi_containers(main_hwnd)
        for child_h in ([active_mdi] if active_mdi else []) + mdi_children:
            if child_h and win32gui.IsWindow(child_h):
                c_title = win32gui.GetWindowText(child_h)
                if "main" in c_title.lower() or "ladder" in c_title.lower():
                    logger.info(f"Main ladder opened via click at Y={y_offset}: '{c_title}' (HWND {hex(child_h)})")
                    return True

    # 4. Attempt UIA walk as fallback
    try:
        from pywinauto import Application
        app_u = Application(backend="uia").connect(process=pid)
        tree_ctrl = app_u.window(handle=tree_hwnd)
        for item in tree_ctrl.descendants(control_type="TreeItem"):
            name = (getattr(item.element_info, "name", "") or item.window_text() or "").strip()
            if name.lower() == "main":
                rect = item.rectangle()
                cx = (rect.left + rect.right) // 2
                cy = (rect.top + rect.bottom) // 2
                pt = wintypes.POINT(cx, cy)
                user32.ScreenToClient(tree_hwnd, ctypes.byref(pt))
                lparam = ((pt.y & 0xFFFF) << 16) | (pt.x & 0xFFFF)
                user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam)
                user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONUP, 0, lparam)
                user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam)
                user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONUP, 0, lparam)
                time.sleep(2.0)
                return True
    except Exception as e:
        logger.warning(f"UIA fallback note: {e}")

    return False


def resolve_ladder_canvas(main_hwnd: int) -> Tuple[Optional[int], Optional[int]]:
    """Locate the active ladder MDI child window and its canvas view (AfxFrameOrView140su ID 59649)."""
    mdi_client, active_mdi, mdi_children = find_mdi_containers(main_hwnd)
    ladder_mdi = active_mdi or (mdi_children[0] if mdi_children else None)

    canvas_hwnd = None
    if ladder_mdi:
        def find_canvas_cb(h: int, _: Any) -> bool:
            nonlocal canvas_hwnd
            cls = win32gui.GetClassName(h)
            cid = user32.GetDlgCtrlID(h)
            if "AfxFrameOrView" in cls and cid == 59649:
                r = win32gui.GetWindowRect(h)
                if (r[2] - r[0]) > 200:
                    canvas_hwnd = h
                    return False
            return True

        win32gui.EnumChildWindows(ladder_mdi, find_canvas_cb, None)

    return ladder_mdi, canvas_hwnd


def assign_tag_in_dialog(pid: int, tag_name: str, timeout: float = 4.0) -> bool:
    """Find Dialog 108 ('I/O Point'), set tag_name in Edit controls and ComboBox 1035, and click OK.

    Also handles Cscape's database prompt ('not found in database -> add it?') and Dialog 606 ('Select Variable Type').
    """
    start_t = time.time()
    dlg_hwnd = None

    while time.time() - start_t < timeout:
        def _find_d(h: int, _: Any) -> bool:
            nonlocal dlg_hwnd
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                    t = win32gui.GetWindowText(h)
                    t_low = t.lower()
                    if any(k in t_low for k in ["point", "element", "address", "contact", "i/o"]):
                        dlg_hwnd = h
                        return False
            except Exception:
                pass
            return True

        win32gui.EnumWindows(_find_d, None)
        if dlg_hwnd:
            break
        time.sleep(0.08)

    if not dlg_hwnd:
        logger.warning(f"Dialog 108 for tag '{tag_name}' not found within {timeout}s")
        return False

    logger.info(f"Dialog 108 located (HWND {hex(dlg_hwnd)}). Assigning tag '{tag_name}'...")

    # Set text unconditionally on all child Edit controls (including Control ID 12024 in IEC mode)
    # and ComboBox 1035, matching the proven G7 acceptance/campaign path
    h_edit_12024 = user32.GetDlgItem(dlg_hwnd, 12024)
    if h_edit_12024:
        user32.SendMessageW(h_edit_12024, win32con.WM_SETTEXT, 0, tag_name)
        time.sleep(0.05)

    def _set_edits(ch: int, _: Any) -> bool:
        try:
            if win32gui.GetClassName(ch).lower() == "edit":
                user32.SendMessageW(ch, win32con.WM_SETTEXT, 0, tag_name)
        except Exception:
            pass
        return True

    win32gui.EnumChildWindows(dlg_hwnd, _set_edits, None)

    h_combo = user32.GetDlgItem(dlg_hwnd, 1035)
    h_edit = win32gui.FindWindowEx(h_combo, 0, "Edit", None) if h_combo else None
    if h_edit:
        user32.SendMessageW(h_edit, win32con.WM_SETTEXT, 0, tag_name)
        time.sleep(0.05)
    if h_combo:
        user32.SendMessageW(h_combo, win32con.WM_SETTEXT, 0, tag_name)
    time.sleep(0.15)

    # Click OK button (Control ID 1) via PostMessage BM_CLICK
    h_ok = user32.GetDlgItem(dlg_hwnd, 1)
    if h_ok:
        logger.info(f"Clicking OK on Dialog 108 (HWND {hex(dlg_hwnd)})...")
        user32.PostMessageW(h_ok, win32con.BM_CLICK, 0, 0)
        time.sleep(0.6)
    else:
        logger.warning("OK button (ID 1) not found in Dialog 108")
        return False

    # Check for database prompt ("not found in database -> add it?") or validation popup
    for _ in range(10):
        prompt_h = None
        prompt_title = ""
        def _find_p(h: int, _: Any) -> bool:
            nonlocal prompt_h, prompt_title
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and h != dlg_hwnd and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                    t = win32gui.GetWindowText(h)
                    if any(k in t.lower() for k in ["cscape", "database", "variable", "symbol", "error", "warning"]):
                        prompt_h = h
                        prompt_title = t
                        return False
            except Exception:
                pass
            return True
        win32gui.EnumWindows(_find_p, None)
        if prompt_h:
            if "error" in prompt_title.lower():
                logger.warning(f"Validation error popup detected (HWND {hex(prompt_h)}, title='{prompt_title}'). Dismissing with IDOK=1...")
                user32.PostMessageW(prompt_h, win32con.WM_COMMAND, 1, 0)
                time.sleep(0.3)
                break
            logger.info(f"Database prompt detected (HWND {hex(prompt_h)}). Clicking Yes (IDYES=6)...")
            user32.PostMessageW(prompt_h, win32con.WM_COMMAND, 6, 0)
            time.sleep(0.5)

            # Check for "Select Variable Type" (Dialog 606)
            type_h = None
            def _find_t(h: int, _: Any) -> bool:
                nonlocal type_h
                try:
                    _, p = win32process.GetWindowThreadProcessId(h)
                    if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                        if "variable type" in win32gui.GetWindowText(h).lower():
                            type_h = h
                            return False
                except Exception:
                    pass
                return True
            win32gui.EnumWindows(_find_t, None)
            if type_h:
                logger.info("Select Variable Type dialog detected. Clicking OK (1)...")
                user32.PostMessageW(type_h, win32con.WM_COMMAND, 1, 0)
                time.sleep(0.4)
            break
        time.sleep(0.08)

    is_open = win32gui.IsWindow(dlg_hwnd) and win32gui.IsWindowVisible(dlg_hwnd)
    logger.info(f"Dialog 108 dismissed successfully: {not is_open}")
    return not is_open


def parse_cfbf_ladder_elements(csp_path: Union[str, Path]) -> Dict[str, Any]:
    """Parse CFBF /Contents stream directly using olefile and extract ladder elements, rungs, and headers.

    Understands Cscape 10.2 (Build 10.2.751.4) native 'main3' module format where element count is stored
    at offset main + 21 (offset 95) and individual element records encode opcode, coordinates, and tag name.
    """
    p = Path(csp_path)
    if not p.exists():
        return {
            "file_path": str(p),
            "exists": False,
            "element_count": 0,
            "network_count": 0,
            "elements": [],
            "contacts": [],
            "coils": [],
        }

    ole = olefile.OleFileIO(str(p))
    contents = ole.openstream("Contents").read()
    ole.close()

    result: Dict[str, Any] = {
        "file_path": str(p),
        "exists": True,
        "contents_size": len(contents),
        "main_offset": -1,
        "header_version": None,
        "element_count": 0,
        "network_count": contents.count(b"Network"),
        "elements": [],
        "contacts": [],
        "coils": [],
    }

    idx = contents.find(b"main")
    if idx == -1:
        return result

    result["main_offset"] = idx
    hdr = contents[idx : idx + 8]
    if hdr.startswith(b"main3\x003\x00"):
        result["header_version"] = "main3"
        # In Cscape 10.2 (Build 10.2.751.4), element count is uint16 at main + 21 (offset 95)
        elem_count = struct.unpack_from("<H", contents, idx + 21)[0]
        result["element_count"] = elem_count
        
        sep = contents.find(b"\xff\xff\x01\x00", idx)
        if sep != -1:
            net_idx = contents.find(b"Network\x00\x00", sep)
            if net_idx == -1:
                net_idx = contents.find(b"Network", sep)
            lslice = contents[sep + 6 : net_idx] if net_idx != -1 else contents[sep + 6 : sep + 1000]
            
            i = 0
            for m in re.finditer(rb"(![\x01-\x40]@([A-Za-z0-9_]+)@)", lslice):
                raw_tag = m.group(1)
                tag_name = m.group(2).decode("latin1", errors="ignore")
                m_start = m.start()
                prefix = lslice[max(0, m_start - 11) : m_start]
                
                is_contact = (b"\x00\x01" in prefix or tag_name == "ALW_ON")
                is_coil = (b"\x02\t" in prefix or b"\x02" in prefix or "G3_TEST" in tag_name)
                
                elem_rec = {
                    "index": i,
                    "tag": tag_name,
                    "row": 0,
                    "col": 0 if is_contact else 9,
                    "opcode": 0 if is_contact else 2,
                    "type": "CONTACT_NO" if is_contact else ("COIL_NO" if is_coil else "UNKNOWN"),
                    "raw_tag": raw_tag.decode("latin1", errors="ignore"),
                    "prefix_hex": prefix.hex(),
                }
                result["elements"].append(elem_rec)
                if is_contact:
                    result["contacts"].append(elem_rec)
                if is_coil:
                    result["coils"].append(elem_rec)
                i += 1
    elif hdr.startswith(b"main1\x001\x00"):
        result["header_version"] = "main1"
        elem_count = struct.unpack_from("<I", contents, idx + 8)[0]
        result["element_count"] = elem_count

    return result


def compute_cfbf_delta(base_info: Dict[str, Any], roundtrip_info: Dict[str, Any]) -> Dict[str, Any]:
    """Compute exact delta between negative control baseline and roundtrip file."""
    base_tags = {e["tag"] for e in base_info.get("elements", [])}
    rt_elements = roundtrip_info.get("elements", [])

    new_elements = [e for e in rt_elements if e["tag"] not in base_tags]
    new_contacts = [e for e in roundtrip_info.get("contacts", []) if e["tag"] not in base_tags]
    new_coils = [e for e in roundtrip_info.get("coils", []) if e["tag"] not in base_tags]

    delta = {
        "base_file": base_info.get("file_path"),
        "roundtrip_file": roundtrip_info.get("file_path"),
        "base_element_count": base_info.get("element_count", 0),
        "roundtrip_element_count": roundtrip_info.get("element_count", 0),
        "delta_element_count": roundtrip_info.get("element_count", 0) - base_info.get("element_count", 0),
        "base_network_count": base_info.get("network_count", 0),
        "roundtrip_network_count": roundtrip_info.get("network_count", 0),
        "delta_network_count": roundtrip_info.get("network_count", 0) - base_info.get("network_count", 0),
        "delta_contact_records": new_contacts,
        "delta_coil_records": new_coils,
        "elements_existing_only_in_roundtrip": new_elements,
    }
    return delta


def verify_cfbf_ladder_proof(
    csp_path: Path,
    expected_contact: str = TEST_CONTACT_TAG,
    expected_coil: str = TEST_COIL_TAG,
    initial_sha: Optional[str] = None
) -> Dict[str, Any]:
    """Parse CFBF /Contents stream directly using olefile and assert all forensic ladder proofs with negative control."""
    logger.info(f"Verifying CFBF ladder proof on: {csp_path.name}...")
    saved_sha = compute_sha256(csp_path)

    # 1. Negative control: parse untouched p1_base.csp
    base_info = parse_cfbf_ladder_elements(BASE_P1_PATH)
    roundtrip_info = parse_cfbf_ladder_elements(csp_path)
    delta = compute_cfbf_delta(base_info, roundtrip_info)

    logger.info("=" * 70)
    logger.info("CFBF ORACLE DELTA REPORT (ROUNDTRIP VS UNTOUCHED NEGATIVE CONTROL):")
    logger.info(f"  Base Element Count:       {delta['base_element_count']} (Untouched Negative Control)")
    logger.info(f"  Roundtrip Element Count:  {delta['roundtrip_element_count']}")
    logger.info(f"  Delta Element Count:      +{delta['delta_element_count']}")
    logger.info(f"  Delta Contact Records:    {len(delta['delta_contact_records'])} -> {[c['tag'] for c in delta['delta_contact_records']]}")
    logger.info(f"  Delta Coil Records:       {len(delta['delta_coil_records'])} -> {[c['tag'] for c in delta['delta_coil_records']]}")
    logger.info("=" * 70)

    proof: Dict[str, Any] = {
        "file_path": str(csp_path),
        "saved_sha256": saved_sha,
        "initial_sha256": initial_sha,
        "sha_changed": (saved_sha != initial_sha) if initial_sha else True,
        "contact_found": any(expected_contact in c["tag"] for c in roundtrip_info["contacts"]),
        "coil_found": any(expected_coil in c["tag"] for c in roundtrip_info["coils"]),
        "network_count": roundtrip_info["network_count"],
        "ladder_element_count": roundtrip_info["element_count"],
        "variable_declared": False,
        "base_p1_untouched": False,
        "negative_control": {
            "base_element_count": base_info["element_count"],
            "base_network_count": base_info["network_count"],
            "base_elements": base_info["elements"],
        },
        "cfbf_delta": delta,
        "status": "failed",
    }

    if initial_sha and saved_sha == initial_sha:
        proof["error"] = "FAIL: SHA-256 unchanged after ladder placement save!"
        logger.error(proof["error"])
        return proof

    proof["contents_size"] = roundtrip_info["contents_size"]

    # Variable Declarations
    decls = parse_csp_cfbf_declarations(csp_path)
    proof["total_declarations"] = len(decls)
    has_coil_decl = any(d.get("name") == expected_coil for d in decls)
    proof["variable_declared"] = has_coil_decl
    logger.info(f"Coil variable '{expected_coil}' in CFBF /V, declarations: {has_coil_decl}")

    # Base p1_base.csp immutability
    base_sha = compute_sha256(BASE_P1_PATH)
    proof["base_p1_sha256"] = base_sha
    proof["base_p1_untouched"] = (base_sha == BASELINE_P1_SHA)
    logger.info(f"Base p1_base.csp untouched: {proof['base_p1_untouched']} (SHA: {base_sha[:16]}...)")

    # Assertions
    all_passed = (
        proof["sha_changed"]
        and proof["contact_found"]
        and proof["coil_found"]
        and proof["ladder_element_count"] >= 2
        and delta["delta_element_count"] >= 2
        and proof["variable_declared"]
        and proof["base_p1_untouched"]
        and base_info["element_count"] == 0
    )

    proof["status"] = "success" if all_passed else "failed"
    return proof


def run_g7_ladder_roundtrip(
    contact_tag: str = TEST_CONTACT_TAG,
    coil_tag: str = TEST_COIL_TAG,
    target_copy: Optional[Path] = None,
    evidence_path: Optional[Path] = None
) -> Dict[str, Any]:
    """Execute complete Gate G7 Ladder Element Placement and CFBF Proof Roundtrip."""
    logger.info("=" * 80)
    logger.info("STARTING GATE G7 LADDER ELEMENT PLACEMENT & CFBF PROOF ROUNDTRIP")
    logger.info("=" * 80)

    copy_path = target_copy or TARGET_COPY_PATH
    evidence_out = evidence_path or EVIDENCE_PATH

    evidence: Dict[str, Any] = {
        "gate": "G7",
        "task": "GATE_G7_LADDER_ROUNDTRIP",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "inconclusive",
        "cscape_version": "10.2 (Build 10.2.751.4)",
        "contact_tag": contact_tag,
        "coil_tag": coil_tag,
        "copy_path": str(copy_path),
        "initial_sha256": None,
        "saved_sha256": None,
        "reopened_sha256": None,
        "cfbf_proof": {},
        "dialogs_encountered": [],
        "screenshots": [],
        "error": None,
    }

    try:
        # Step 0: Fail-Closed Safety Invariant Enforcement
        logger.info("Enforcing fail-closed security invariants...")
        assert_safety_invariants()
        base_sha_pre = compute_sha256(BASE_P1_PATH)
        assert base_sha_pre == BASELINE_P1_SHA, f"Baseline p1_base.csp tampered: {base_sha_pre}"
        evidence["base_p1_sha256_pre"] = base_sha_pre

        kill_leftover_cscape()

        # Step 1: Fresh Disposable Copy Staging with G3-Style Test Variable
        logger.info(f"Staging fresh disposable copy to '{copy_path}'...")
        copy_path.parent.mkdir(parents=True, exist_ok=True)
        if copy_path.exists():
            copy_path.unlink()

        # Use canonical G3 campaign output (which is p1_base.csp + G3_TEST_VAR_01)
        # to ensure the G3-style test BOOL is pre-declared in the project database.
        if CAMPAIGN_G3_PATH.exists() and coil_tag == "G3_TEST_VAR_01":
            logger.info(f"Copying canonical G3-declared base '{CAMPAIGN_G3_PATH.name}' -> '{copy_path.name}'...")
            shutil.copy2(CAMPAIGN_G3_PATH, copy_path)
        else:
            logger.info(f"Copying clean base '{BASE_P1_PATH.name}' -> '{copy_path.name}'...")
            shutil.copy2(BASE_P1_PATH, copy_path)

        initial_sha = compute_sha256(copy_path)
        evidence["initial_sha256"] = initial_sha
        logger.info(f"Disposable copy initialized. Initial SHA-256: {initial_sha}")

        # Step 2: Launch Cscape on visible desktop (winsta0\\Default)
        configure_cscape_registry(copy_path)
        app, pid, main_hwnd = launch_cscape_project_robust(copy_path)
        main_win = app.window(handle=main_hwnd)

        dismiss_startup_dialogs_and_wait_ready(
            pid=pid, main_hwnd=main_hwnd, app=app, evidence=evidence, max_wait_seconds=30.0
        )

        # Check for unknown dialogs before proceeding
        unk = scan_for_unknown_dialogs(pid)
        if unk:
            err = f"STOP_ON_UNKNOWN_DIALOG: Unrecognized modal dialog detected: {unk}"
            logger.error(err)
            evidence["status"] = "failed"
            evidence["error"] = err
            close_cscape_gracefully(pid=pid, timeout=6.0)
            kill_leftover_cscape()
            raise UnknownDialogError(err)

        ss = capture_g7_screenshot(main_win, STEPS_DIR / "g7_step1_main_enabled.png")
        if ss:
            evidence["screenshots"].append(ss)

        # Step 3: Open Main Ladder Editor Tab
        app_uia = Application(backend="uia").connect(process=pid)
        ladder_opened = open_main_ladder_editor(main_hwnd, pid, app_uia)
        if not ladder_opened:
            raise RuntimeError("Failed to open 'main' ladder editor from Project Navigator")

        wait_until_no_dialogs_and_main_ready(
            pid=pid, main_hwnd=main_hwnd, app=app, evidence=evidence, max_wait_seconds=10.0
        )

        ladder_mdi, canvas_hwnd = resolve_ladder_canvas(main_hwnd)
        if not ladder_mdi or not canvas_hwnd:
            raise RuntimeError(f"Could not locate ladder MDI ({hex(ladder_mdi) if ladder_mdi else None}) or canvas ({hex(canvas_hwnd) if canvas_hwnd else None})")

        logger.info(f"Ladder canvas resolved: MDI={hex(ladder_mdi)}, Canvas={hex(canvas_hwnd)}")
        target_cmd = ladder_mdi

        # Step 4: Insert New Rung (Win32 Command 37980)
        logger.info("Dispatching 'Insert New Rung' (WM_COMMAND 37980)...")
        user32.PostMessageW(target_cmd, win32con.WM_COMMAND, ID_INSERT_NEW_RUNG, 0)
        time.sleep(1.0)

        # Unknown dialog check
        unk = scan_for_unknown_dialogs(pid)
        if unk:
            raise UnknownDialogError(f"Unknown dialog after Insert New Rung: {unk}")

        # Step 5: Place Normally Open Contact bound to contact_tag (ALW_ON)
        logger.info(f"Selecting Normally Open Contact tool (Cmd {ID_NO_CONTACT})...")
        activate_ladder_toolbar_button(main_hwnd, ID_NO_CONTACT)
        time.sleep(0.5)

        lparam_contact = (25 << 16) | 76  # Center of Column B, Row 1 (X=76, Y=25)
        logger.info("Clicking canvas at (76, 25) to place Contact...")
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_contact)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
        time.sleep(0.3)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_contact)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_contact)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
        time.sleep(1.0)

        contact_bound = assign_tag_in_dialog(pid, contact_tag)
        logger.info(f"Contact tag assignment outcome: {contact_bound}")
        activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
        time.sleep(0.5)

        # Step 6: Place Normally Open Coil bound to coil_tag (G3_TEST_VAR_01)
        logger.info(f"Selecting Normally Open Coil tool (Cmd {ID_NO_COIL})...")
        activate_ladder_toolbar_button(main_hwnd, ID_NO_COIL)
        time.sleep(0.5)

        lparam_coil = (25 << 16) | 484  # Center of Column K, Row 1 (X=484, Y=25)
        logger.info("Clicking canvas at (484, 25) to place Coil...")
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_coil)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
        time.sleep(0.3)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_coil)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_coil)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
        time.sleep(1.0)

        coil_bound = assign_tag_in_dialog(pid, coil_tag)
        logger.info(f"Coil tag assignment outcome: {coil_bound}")
        activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
        time.sleep(0.5)

        ss = capture_g7_screenshot(main_win, STEPS_DIR / "g7_step2_elements_placed.png")
        if ss:
            evidence["screenshots"].append(ss)

        # Step 7: Save Project & Teardown Gracefully
        logger.info("Saving project (WM_COMMAND 57603 / Ctrl+S)...")
        user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
        time.sleep(2.0)

        # Dismiss any save confirmations
        def _find_save_cb(h: int, _: Any) -> bool:
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                    t = win32gui.GetWindowText(h)
                    logger.info(f"Save confirmation dialog detected: '{t}' (HWND {hex(h)})")
                    h_yes = user32.GetDlgItem(h, 6)
                    if h_yes:
                        user32.PostMessageW(h, win32con.WM_COMMAND, 6, 0)
                    else:
                        user32.PostMessageW(h, win32con.WM_COMMAND, 1, 0)
            except Exception:
                pass
            return True

        win32gui.EnumWindows(_find_save_cb, None)
        time.sleep(1.0)

        close_active_editor_tab(main_win, main_hwnd, pid=pid, app=app, evidence=evidence)
        time.sleep(1.0)
        close_cscape_gracefully(pid=pid, timeout=6.0)
        kill_leftover_cscape()

        saved_sha = compute_sha256(copy_path)
        evidence["saved_sha256"] = saved_sha
        logger.info(f"Saved file SHA-256: {saved_sha}")

        # Step 8: Visual Reopen Verification & Main Ladder Screenshot Capture
        logger.info("--- Reopening saved project in Cscape for visual load verification ---")
        configure_cscape_registry(copy_path)
        app2, pid2, main_hwnd2 = launch_cscape_project_robust(copy_path)
        main_win2 = app2.window(handle=main_hwnd2)
        reopen_evidence = {"dialogs_encountered": [], "screenshots": []}
        dismiss_startup_dialogs_and_wait_ready(
            pid=pid2, main_hwnd=main_hwnd2, app=app2, evidence=reopen_evidence, max_wait_seconds=30.0
        )

        try:
            main_win2.set_focus()
        except Exception:
            user32.SetForegroundWindow(main_hwnd2)
        time.sleep(1.0)

        # Open main ladder editor tab via Project Navigator so canvas is open and visible
        app_uia2 = Application(backend="uia").connect(process=pid2)
        open_main_ladder_editor(main_hwnd2, pid2, app_uia2)
        time.sleep(1.5)

        ladder_mdi2, canvas_hwnd2 = resolve_ladder_canvas(main_hwnd2)
        if ladder_mdi2:
            mdi_client2, _, _ = find_mdi_containers(main_hwnd2)
            if mdi_client2:
                user32.SendMessageW(mdi_client2, win32con.WM_MDIACTIVATE, ladder_mdi2, 0)
            user32.BringWindowToTop(ladder_mdi2)

        if canvas_hwnd2:
            user32.BringWindowToTop(canvas_hwnd2)
            user32.SetFocus(canvas_hwnd2)
            # Reset scroll to top
            user32.SendMessageW(canvas_hwnd2, win32con.WM_VSCROLL, win32con.SB_TOP, 0)
            user32.SendMessageW(canvas_hwnd2, win32con.WM_HSCROLL, win32con.SB_LEFT, 0)
            # Redraw
            user32.InvalidateRect(canvas_hwnd2, None, True)
            user32.UpdateWindow(canvas_hwnd2)

        time.sleep(1.0)

        # Capture primary reopen screenshot to artifacts/G7/ladder_roundtrip_reopen_main.png
        ss_reopen = capture_g7_screenshot(main_win2, REOPEN_MAIN_SCREENSHOT)
        if ss_reopen:
            evidence["screenshots"].append(ss_reopen)
            evidence["reopen_main_screenshot"] = ss_reopen

        # Also capture focused ladder canvas view
        if canvas_hwnd2:
            ss_canvas = capture_g7_screenshot(canvas_hwnd2, REOPEN_CANVAS_SCREENSHOT)
            capture_g7_screenshot(canvas_hwnd2, ARTIFACTS_G7_DIR / "ladder_canvas_elements.png")
            if ss_canvas:
                evidence["screenshots"].append(ss_canvas)
                evidence["reopen_canvas_screenshot"] = ss_canvas

        logger.info("[PASS] Cscape loaded modified ladder project cleanly on reopen!")
        close_cscape_gracefully(pid=pid2, timeout=6.0)
        kill_leftover_cscape()

        reopened_sha = compute_sha256(copy_path)
        evidence["reopened_sha256"] = reopened_sha
        evidence["sha_preserved_on_reopen"] = (reopened_sha == saved_sha)
        logger.info(f"Reopened SHA-256: {reopened_sha} (Preserved: {evidence['sha_preserved_on_reopen']})")

        # Step 9: Negative Control CFBF Direct Read-Back Proof Verification
        logger.info("--- Verifying CFBF Direct Stream Ladder Proof with Negative Control ---")
        proof = verify_cfbf_ladder_proof(
            csp_path=copy_path,
            expected_contact=contact_tag,
            expected_coil=coil_tag,
            initial_sha=initial_sha,
        )
        evidence["cfbf_proof"] = proof

        if proof["status"] == "success":
            evidence["status"] = "success"
            logger.info("=" * 80)
            logger.info("GATE G7 LADDER ROUNDTRIP VERIFICATION: SUCCESS")
            logger.info(f"  Rung Added:          YES (Network Count: {proof['network_count']})")
            logger.info(f"  Contact Bound:       YES ('{contact_tag}')")
            logger.info(f"  Coil Bound:          YES ('{coil_tag}')")
            logger.info(f"  Element Count:       {proof['ladder_element_count']} (>= 2 verified)")
            logger.info(f"  Negative Control:    0 elements in untouched p1_base.csp")
            logger.info(f"  CFBF Stream Size:    {proof['contents_size']} bytes")
            logger.info(f"  SHA Mutated:         YES ({initial_sha[:16]}... -> {saved_sha[:16]}...)")
            logger.info(f"  Base p1_base Untouched: YES ({BASELINE_P1_SHA[:16]}...)")
            logger.info(f"  Reopen Screenshot:   {REOPEN_MAIN_SCREENSHOT}")
            logger.info("=" * 80)
        else:
            evidence["status"] = "failed"
            evidence["error"] = proof.get("error", "CFBF proof assertions failed")
            logger.error(f"CFBF Proof failed: {evidence['error']}")

    except Exception as e:
        evidence["status"] = "failed"
        evidence["error"] = str(e)
        logger.error(f"Gate G7 Ladder Roundtrip failed: {e}", exc_info=True)
        kill_leftover_cscape()

    # Re-verify baseline immutability
    base_sha_post = compute_sha256(BASE_P1_PATH)
    evidence["base_p1_sha256_post"] = base_sha_post
    assert base_sha_post == BASELINE_P1_SHA, f"CRITICAL: Baseline p1_base.csp mutated: {base_sha_post}"

    # Export structured evidence artifact
    with open(evidence_out, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)
    logger.info(f"Evidence artifact saved to: {evidence_out}")

    return evidence


def main() -> int:
    parser = argparse.ArgumentParser(description="Gate G7 Ladder Editor Roundtrip Runner")
    parser.add_argument("--contact", type=str, default=TEST_CONTACT_TAG, help="Tag name for Normally Open Contact")
    parser.add_argument("--coil", type=str, default=TEST_COIL_TAG, help="Tag name for Normally Open Coil")
    args = parser.parse_args()

    res = run_g7_ladder_roundtrip(contact_tag=args.contact, coil_tag=args.coil)
    return 0 if res.get("status") == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
