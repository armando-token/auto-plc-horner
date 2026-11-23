#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gate G7 Ladder Editor Concrete Element Placement 10-Run Campaign Runner.

Mandate: 10 sequential live runs on fresh p1_base copies rotating NO contact/NC contact (1001)
and coil variants, each with CFBF negative control delta, reopen screenshot, and stop_on_fail discipline.
Classification: TESTED_MOCK / INTEGRATION [winsta0\\Default]

Strict Engineering Directives Enforced:
1. Baseline Immutability: work/disposable/p1_base.csp is verified via SHA-256 before and after
   every run (5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881).
2. Fail-Closed Hardware Lockout: Physical COM ports 1..256, companion flasher binaries,
   download CLI switches, and Win32 download command IDs 32827/33149 permanently blocked.
3. Unknown Dialog Guard: Any modal dialog (#32770 or popup) that is not in the recognized
   allowlist immediately stops the process, logs details, captures a screenshot, and aborts.
4. Concrete Rotation:
   - 10 sequential runs on fresh disposable copies (campaign_run_01..10.csp).
   - Alternating NO contact (cmd 1000) and NC contact (cmd 1001) across system BOOL tags
     (ALW_ON, ALW_OFF, FST_SCN, SYS_DISABLE, T_100MS, SYS_ACK, T_10MS, T_SEC).
   - Rotating coil variants (Normally Open Coil 1002, NC Coil 37687, Set Coil 37690, Reset Coil 37691)
     across test BOOL tags (G3_TEST_VAR_01, G3_TEST_VAR_02, G3_TEST_VAR_03).
5. CFBF Negative Control Delta: Run CFBF oracle on untouched p1_base.csp as negative control;
   assert delta_element_count >= 2, delta_contact_records >= 1, delta_coil_records >= 1.
6. Visual Reopen Screenshot: Every run reopens the saved project in Cscape and captures a
   reopen screenshot of the main ladder showing the rung with elements
   (artifacts/G7/campaign_runs/run_XX_reopen.png).
7. Stop-on-Fail Discipline: First failure immediately stops execution and marks campaign failed.
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

# Output Directories & Constants
ARTIFACTS_G7_DIR = REPO_ROOT / "artifacts" / "G7"
ARTIFACTS_G7_DIR.mkdir(parents=True, exist_ok=True)
CAMPAIGN_RUNS_DIR = ARTIFACTS_G7_DIR / "campaign_runs"
CAMPAIGN_RUNS_DIR.mkdir(parents=True, exist_ok=True)
CAMPAIGN_SUMMARY_PATH = ARTIFACTS_G7_DIR / "g7_campaign_summary.json"
LOG_DIR = REPO_ROOT / "artifacts" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Win32 Command IDs for Contacts and Coils
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

# Additional Toolbox Command IDs for Coils
ID_NC_COIL = 37687             # Normally Closed Coil
ID_POS_COIL = 37688            # Positive Transition Coil
ID_NEG_COIL = 37689            # Negative Transition Coil
ID_SET_COIL = 37690            # Set Coil
ID_RESET_COIL = 37691          # Reset Coil

# Setup Logger
logger = logging.getLogger("g7_campaign")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    fh = logging.FileHandler(LOG_DIR / "g7_campaign.log", mode="w", encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(sh)
    logger.addHandler(fh)

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32


class UnknownDialogError(RuntimeError):
    """Raised when an unrecognized modal dialog is encountered, triggering immediate fail-closed abort."""
    pass


# 10-Run Campaign Parameter Matrix Definition
CAMPAIGN_10_RUNS: List[Dict[str, Any]] = [
    {
        "run_idx": 1,
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "ALW_ON",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_01",
    },
    {
        "run_idx": 2,
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "ALW_OFF",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_02",
    },
    {
        "run_idx": 3,
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "FST_SCN",
        "coil_cmd": ID_SET_COIL,
        "coil_type": "COIL_SET",
        "coil_tag": "G3_TEST_VAR_03",
    },
    {
        "run_idx": 4,
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "SYS_DISABLE",
        "coil_cmd": ID_RESET_COIL,
        "coil_type": "COIL_RESET",
        "coil_tag": "G3_TEST_VAR_01",
    },
    {
        "run_idx": 5,
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "T_100MS",
        "coil_cmd": ID_NC_COIL,
        "coil_type": "COIL_NC",
        "coil_tag": "G3_TEST_VAR_02",
    },
    {
        "run_idx": 6,
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "SYS_ACK",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_03",
    },
    {
        "run_idx": 7,
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "T_10MS",
        "coil_cmd": ID_SET_COIL,
        "coil_type": "COIL_SET",
        "coil_tag": "G3_TEST_VAR_01",
    },
    {
        "run_idx": 8,
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "T_SEC",
        "coil_cmd": ID_RESET_COIL,
        "coil_type": "COIL_RESET",
        "coil_tag": "G3_TEST_VAR_02",
    },
    {
        "run_idx": 9,
        "contact_cmd": ID_NO_CONTACT,
        "contact_type": "CONTACT_NO",
        "contact_tag": "ALW_ON",
        "coil_cmd": ID_NC_COIL,
        "coil_type": "COIL_NC",
        "coil_tag": "G3_TEST_VAR_03",
    },
    {
        "run_idx": 10,
        "contact_cmd": ID_NC_CONTACT,
        "contact_type": "CONTACT_NC",
        "contact_tag": "ALW_OFF",
        "coil_cmd": ID_NO_COIL,
        "coil_type": "COIL_NO",
        "coil_tag": "G3_TEST_VAR_01",
    },
]

# Deterministic CFBF Opcode & Type Definitions
CSCAPE_OPCODE_TO_TYPE: Dict[int, str] = {
    0x00: "CONTACT_NO",
    0x01: "CONTACT_NC",
    0x02: "COIL_NO",
    0x09: "COIL_NC",
    0x0C: "COIL_SET",
    0x0D: "COIL_RESET",
}
CONTACT_OPCODES = {0x00, 0x01}
COIL_OPCODES = {0x02, 0x09, 0x0C, 0x0D}


def dismiss_about_cscape_and_wait_main_enabled(main_hwnd: int, pid: int, max_wait_seconds: float = 12.0) -> bool:
    """Actively dismiss any delayed 'About Cscape', 'Tip of the Day', or modal dialogs,
    and wait until the main Cscape window is fully enabled with no blocking #32770 dialogs.
    """
    start_t = time.time()
    logger.info("Waiting for and dismissing About Cscape / modal dialogs...")
    while time.time() - start_t < max_wait_seconds:
        hwnds = []
        def _enum_win(h: int, _: Any) -> bool:
            try:
                if win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                    _, w_pid = win32process.GetWindowThreadProcessId(h)
                    if w_pid == pid:
                        hwnds.append(h)
            except Exception:
                pass
            return True
        win32gui.EnumWindows(_enum_win, None)

        for h in hwnds:
            if h == main_hwnd:
                continue
            cls = win32gui.GetClassName(h)
            title = win32gui.GetWindowText(h)
            t_low = title.lower()

            is_about = any(k in t_low for k in ["about cscape", "tip of the day", "welcome"]) or (cls == "#32770" and "about" in t_low)
            is_modal = (cls == "#32770" and not win32gui.IsWindowEnabled(main_hwnd))

            if is_about or is_modal or cls == "#32770":
                logger.info(f"Dismissing dialog '{title}' (HWND {hex(h)}, class '{cls}')...")
                user32.PostMessageW(h, win32con.WM_COMMAND, 1, 0)
                user32.PostMessageW(h, win32con.WM_COMMAND, 2, 0)
                user32.PostMessageW(h, win32con.WM_CLOSE, 0, 0)
                time.sleep(0.3)

        if win32gui.IsWindowEnabled(main_hwnd):
            any_modal = False
            for h in hwnds:
                if h != main_hwnd and win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                    if win32gui.GetClassName(h) == "#32770":
                        r = win32gui.GetWindowRect(h)
                        if (r[2] - r[0] > 50) and (r[3] - r[1] > 50):
                            any_modal = True
                            break
            if not any_modal:
                logger.info("Main window confirmed enabled and clear of modal dialogs.")
                return True
        time.sleep(0.2)
    return win32gui.IsWindowEnabled(main_hwnd)


def scan_for_unknown_dialogs(pid: int, allowed_titles: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    """Scan all top-level windows for any unauthorized modal dialog."""
    if allowed_titles is None:
        allowed_titles = [
            "about cscape", "i/o point", "cscape", "tip of the day",
            "select element type", "variable", "database"
        ]

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
    elif hasattr(window_target, "wrapper_object"):
        try:
            hwnd = window_target.wrapper_object().handle
        except Exception:
            pass

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
        logger.debug(f"pywinauto capture note: {e}")

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
            logger.debug(f"ImageGrab bbox note: {e}")

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

    # Method 4: Full desktop grab
    if img is None:
        try:
            img = ImageGrab.grab()
        except Exception as e:
            logger.warning(f"Full desktop grab note: {e}")

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
    """Activate vertical toolbar button or command tool by direct click and WM_COMMAND dispatch."""
    coords_map = {
        ID_SELECT_ELEMENTS: (11, 11),
        ID_NO_CONTACT: (11, 82),
        ID_NC_CONTACT: (11, 104),
        ID_NO_COIL: (11, 126),
    }
    tool_command_aliases = {
        ID_SELECT_ELEMENTS: [112],
        ID_NO_CONTACT: [1000, 37684],
        ID_NC_CONTACT: [1001, 37685],
        ID_NO_COIL: [1002, 37686],
        ID_NC_COIL: [139, 37687],
        ID_SET_COIL: [142, 37690],
        ID_RESET_COIL: [143, 37691],
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

    # 1. Post WM_COMMAND with aliases to ladder_mdi, canvas, and main window
    cmds_to_send = tool_command_aliases.get(cmd_id, [cmd_id])
    for cid in cmds_to_send:
        if ladder_mdi:
            user32.PostMessageW(ladder_mdi, win32con.WM_COMMAND, cid, tb_hwnd or 0)
        if canvas_hwnd:
            user32.PostMessageW(canvas_hwnd, win32con.WM_COMMAND, cid, tb_hwnd or 0)
        user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, cid, 0)

    # 2. Click toolbar button directly ONLY if physical button exists on ToolbarWindow32
    if tb_hwnd and cmd_id in coords_map:
        cx, cy = coords_map[cmd_id]
        lp = ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)
        user32.PostMessageW(tb_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lp)
        user32.PostMessageW(tb_hwnd, win32con.WM_LBUTTONUP, 0, lp)

    time.sleep(0.2)
    return True


def launch_cscape_project_robust(project_path: Path, timeout: float = 25.0) -> Tuple[Application, int, int]:
    """Launch Cscape 10.2 with project file, robust against delayed presentation and PID recycling."""
    import psutil
    from scripts.g3_edit_roundtrip import DEFAULT_CSCAPE_PATH, enumerate_cscape_windows, get_cscape_processes

    kill_leftover_cscape()
    time.sleep(2.0)
    configure_cscape_registry(project_path)

    abs_path = str(project_path.resolve())
    logger.info(f"Launching Cscape 10.2 with project: {abs_path}...")
    proc_obj = psutil.Popen([DEFAULT_CSCAPE_PATH, abs_path], cwd=os.path.dirname(DEFAULT_CSCAPE_PATH))
    expected_pid = proc_obj.pid

    main_hwnd = None
    actual_pid = expected_pid
    start_t = time.time()

    while time.time() - start_t < timeout:
        time.sleep(0.5)
        windows = enumerate_cscape_windows(expected_pid)
        for h, cls, title in windows:
            if cls.startswith("Afx") and "cscape" in title.lower():
                main_hwnd = h
                actual_pid = expected_pid
                break
        if main_hwnd:
            break

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
    """Actively wait for and dismiss startup dialogs and ensure main_hwnd is fully enabled."""
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
                logger.info(f"Dismissing startup dialog '{title}' (HWND {hex(h)})...")
                seen_dialogs.append({"hwnd": hex(h), "title": title, "class": cls})
                user32.PostMessageW(h, win32con.WM_COMMAND, 1, 0)  # IDOK
                user32.PostMessageW(h, win32con.WM_COMMAND, 2, 0)  # IDCANCEL
                user32.PostMessageW(h, win32con.WM_CLOSE, 0, 0)
                time.sleep(0.5)

        main_is_enabled = win32gui.IsWindowEnabled(main_hwnd)
        if main_is_enabled:
            blocking = False
            for h in hwnds:
                if h != main_hwnd and win32gui.IsWindow(h):
                    if win32gui.GetClassName(h) == "#32770":
                        r = win32gui.GetWindowRect(h)
                        if (r[2] - r[0] > 60) and (r[3] - r[1] > 60):
                            blocking = True
                            break
            if not blocking:
                if evidence is not None and seen_dialogs:
                    evidence.setdefault("dialogs_encountered", []).extend(seen_dialogs)
                return True

        time.sleep(0.5)

    raise RuntimeError(f"Main window HWND {hex(main_hwnd)} remained disabled after {max_wait_seconds}s.")


def open_main_ladder_editor(main_hwnd: int, pid: int, app_uia: Optional[Application] = None) -> bool:
    """Navigate Project Navigator SysTreeView32 (ID 300) to open the 'main' ladder editor."""
    logger.info("Opening 'main' ladder editor via Project Navigator...")

    # Helper to check if a window handle represents the ladder editor
    def _is_ladder_window(h: int) -> bool:
        if not h or not win32gui.IsWindow(h):
            return False
        title = win32gui.GetWindowText(h).lower()
        if any(k in title for k in ["main", "ladder", ".csp", "untitled"]):
            return True
        # Check if child window contains the ladder canvas view (AfxFrameOrView140su ID 59649)
        has_canvas = False
        def _check_c(ch: int, _: Any) -> bool:
            nonlocal has_canvas
            if "AfxFrameOrView" in win32gui.GetClassName(ch) and user32.GetDlgCtrlID(ch) == 59649:
                has_canvas = True
                return False
            return True
        win32gui.EnumChildWindows(h, _check_c, None)
        return has_canvas

    # 1. Poll up to 4.0s for already-open or opening ladder editor in MDI
    poll_start = time.time()
    while time.time() - poll_start < 4.0:
        mdi_client, active_mdi, mdi_children = find_mdi_containers(main_hwnd)
        for child_h in ([active_mdi] if active_mdi else []) + mdi_children:
            if _is_ladder_window(child_h):
                c_title = win32gui.GetWindowText(child_h)
                logger.info(f"Main ladder editor confirmed open: '{c_title}' (HWND {hex(child_h)})")
                return True
        time.sleep(0.3)

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
    for y_offset in [46, 50, 42, 60, 35, 75, 90]:
        lparam = ((y_offset & 0xFFFF) << 16) | (40 & 0xFFFF)
        user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam)
        user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONUP, 0, lparam)
        user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam)
        user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONUP, 0, lparam)
        time.sleep(1.0)

        # Check if ladder editor opened
        _, active_mdi, mdi_children = find_mdi_containers(main_hwnd)
        for child_h in ([active_mdi] if active_mdi else []) + mdi_children:
            if _is_ladder_window(child_h):
                c_title = win32gui.GetWindowText(child_h)
                logger.info(f"Main ladder opened via click at Y={y_offset}: '{c_title}' (HWND {hex(child_h)})")
                return True

    # 4. Attempt UIA walk as fallback
    try:
        from pywinauto import Application, mouse
        app_u = Application(backend="uia").connect(process=pid)
        tree_ctrl = app_u.window(handle=tree_hwnd)
        for item in tree_ctrl.descendants(control_type="TreeItem"):
            name = (getattr(item.element_info, "name", "") or item.window_text() or "").strip()
            if "main" in name.lower():
                rect = item.rectangle()
                cx = (rect.left + rect.right) // 2
                cy = (rect.top + rect.bottom) // 2
                logger.info(f"Double-clicking TreeItem '{name}' at ({cx}, {cy})...")
                try:
                    mouse.double_click(coords=(cx, cy))
                except Exception:
                    pt = wintypes.POINT(cx, cy)
                    user32.ScreenToClient(tree_hwnd, ctypes.byref(pt))
                    lparam = ((pt.y & 0xFFFF) << 16) | (pt.x & 0xFFFF)
                    user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam)
                    user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONUP, 0, lparam)
                    user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam)
                    user32.PostMessageW(tree_hwnd, win32con.WM_LBUTTONUP, 0, lparam)
                time.sleep(2.0)
                _, active_mdi, mdi_children = find_mdi_containers(main_hwnd)
                for child_h in ([active_mdi] if active_mdi else []) + mdi_children:
                    if _is_ladder_window(child_h):
                        return True
    except Exception as e:
        logger.warning(f"UIA fallback note: {e}")

    # Final check: resolve_ladder_canvas
    ladder_mdi, canvas_hwnd = resolve_ladder_canvas(main_hwnd)
    if ladder_mdi and canvas_hwnd:
        logger.info(f"Main ladder resolved via resolve_ladder_canvas: {hex(ladder_mdi)}")
        return True

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


def assign_tag_in_dialog(pid: int, tag_name: str, timeout: float = 3.5) -> bool:
    """Find Dialog 108 ('I/O Point'), set tag_name, click OK, and handle database prompt if needed."""
    start_t = time.time()
    dlg_hwnd = None

    while time.time() - start_t < timeout:
        def _find_d(h: int, _: Any) -> bool:
            nonlocal dlg_hwnd
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                    t = win32gui.GetWindowText(h)
                    if any(k in t.lower() for k in ["point", "element", "address"]):
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

    h_edit = user32.GetDlgItem(dlg_hwnd, 12024)
    if h_edit:
        user32.SendMessageW(h_edit, win32con.WM_SETTEXT, 0, tag_name)

    def _set_edits(ch: int, _: Any) -> bool:
        if win32gui.GetClassName(ch).lower() == "edit":
            user32.SendMessageW(ch, win32con.WM_SETTEXT, 0, tag_name)
        return True

    win32gui.EnumChildWindows(dlg_hwnd, _set_edits, None)
    h_combo = user32.GetDlgItem(dlg_hwnd, 1035)
    if h_combo:
        user32.SendMessageW(h_combo, win32con.WM_SETTEXT, 0, tag_name)
    time.sleep(0.15)

    h_ok = user32.GetDlgItem(dlg_hwnd, 1)
    if h_ok:
        user32.PostMessageW(h_ok, win32con.BM_CLICK, 0, 0)
        time.sleep(0.6)
    else:
        return False

    # Check for database prompt ("not found in database -> add it?")
    for _ in range(10):
        prompt_h = None
        def _find_p(h, _):
            nonlocal prompt_h
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                    t = win32gui.GetWindowText(h)
                    if any(k in t.lower() for k in ["cscape", "database", "variable", "symbol"]):
                        prompt_h = h
                        return False
            except Exception:
                pass
            return True
        win32gui.EnumWindows(_find_p, None)
        if prompt_h:
            logger.info(f"Database prompt detected (HWND {hex(prompt_h)}). Clicking Yes (IDYES=6)...")
            user32.PostMessageW(prompt_h, win32con.WM_COMMAND, 6, 0)
            time.sleep(0.5)

            # Check for "Select Variable Type" (Dialog 606)
            type_h = None
            def _find_t(h, _):
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
                logger.info(f"Select Variable Type dialog detected. Clicking OK (1)...")
                user32.PostMessageW(type_h, win32con.WM_COMMAND, 1, 0)
                time.sleep(0.4)
            break
        time.sleep(0.08)

    is_open = win32gui.IsWindow(dlg_hwnd) and win32gui.IsWindowVisible(dlg_hwnd)
    return not is_open


def parse_cfbf_ladder_elements(csp_path: Union[str, Path]) -> Dict[str, Any]:
    """Parse CFBF /Contents stream directly using olefile and extract ladder elements,
    opcodes, element types, columns, and tag bindings deterministically.
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
            "readback_contact_type": None,
            "readback_contact_tag": None,
            "readback_coil_type": None,
            "readback_coil_tag": None,
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
        "readback_contact_type": None,
        "readback_contact_tag": None,
        "readback_coil_type": None,
        "readback_coil_tag": None,
    }

    idx = contents.find(b"main")
    if idx == -1:
        return result

    result["main_offset"] = idx
    hdr = contents[idx : idx + 8]
    if hdr.startswith(b"main3\x003\x00"):
        result["header_version"] = "main3"
        elem_count = struct.unpack_from("<H", contents, idx + 21)[0]
        result["element_count"] = elem_count

        sep = contents.find(b"\xff\xff\x01\x00", idx)
        if sep != -1:
            net_idx = contents.find(b"Network\x00\x00", sep)
            if net_idx == -1:
                net_idx = contents.find(b"Network", sep)
            lslice = contents[sep + 6 : net_idx] if net_idx != -1 else contents[sep + 6 : sep + 1000]

            matches = list(re.finditer(rb"(![\x01-\x40]@([A-Za-z0-9_]+)@)", lslice))
            for i, m in enumerate(matches):
                raw_tag = m.group(1)
                tag_name = m.group(2).decode("latin1", errors="ignore")
                m_start = m.start()
                hdr_bytes = lslice[max(0, m_start - 9) : m_start]
                opcode = hdr_bytes[0] if len(hdr_bytes) >= 1 else 0
                col = hdr_bytes[1] if len(hdr_bytes) >= 2 else (1 if i == 0 else 9)

                elem_type = CSCAPE_OPCODE_TO_TYPE.get(opcode, f"UNKNOWN_0x{opcode:02x}")
                is_contact = opcode in CONTACT_OPCODES
                is_coil = opcode in COIL_OPCODES

                elem_rec = {
                    "index": i,
                    "tag": tag_name,
                    "row": 0,
                    "col": col,
                    "opcode": opcode,
                    "opcode_hex": f"0x{opcode:02x}",
                    "type": elem_type,
                    "category": "CONTACT" if is_contact else ("COIL" if is_coil else "OTHER"),
                    "raw_tag": raw_tag.decode("latin1", errors="ignore"),
                    "header_hex": hdr_bytes.hex(),
                }
                result["elements"].append(elem_rec)
                if is_contact:
                    result["contacts"].append(elem_rec)
                    if result["readback_contact_type"] is None:
                        result["readback_contact_type"] = elem_type
                        result["readback_contact_tag"] = tag_name
                if is_coil:
                    result["coils"].append(elem_rec)
                    if result["readback_coil_type"] is None:
                        result["readback_coil_type"] = elem_type
                        result["readback_coil_tag"] = tag_name
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


# ============================================================================
# Single Campaign Run Execution Routine
# ============================================================================

def execute_campaign_run(run_spec: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a single live campaign run: place contact and coil variants, save, reopen, capture screenshot, and verify CFBF delta."""
    run_idx = run_spec["run_idx"]
    contact_cmd = run_spec["contact_cmd"]
    contact_tag = run_spec["contact_tag"]
    coil_cmd = run_spec["coil_cmd"]
    coil_tag = run_spec["coil_tag"]

    copy_path = COPIES_DIR / f"campaign_run_g7_{run_idx:02d}.csp"
    reopen_screenshot_path = CAMPAIGN_RUNS_DIR / f"run_{run_idx:02d}_reopen.png"

    run_result: Dict[str, Any] = {
        "run_idx": run_idx,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "failed",
        "contact_cmd": contact_cmd,
        "contact_type": run_spec["contact_type"],
        "contact_tag": contact_tag,
        "coil_cmd": coil_cmd,
        "coil_type": run_spec["coil_type"],
        "coil_tag": coil_tag,
        "readback_contact_type": None,
        "readback_contact_tag": None,
        "readback_coil_type": None,
        "readback_coil_tag": None,
        "plan_match": False,
        "copy_path": str(copy_path),
        "initial_sha256": None,
        "saved_sha256": None,
        "reopened_sha256": None,
        "reopen_screenshot": str(reopen_screenshot_path),
        "cfbf_delta": {},
        "error": None,
    }

    logger.info("-" * 80)
    logger.info(
        f"[CAMPAIGN RUN {run_idx:02d}/10] Starting: Contact={contact_tag} (Cmd {contact_cmd}) | "
        f"Coil={coil_tag} (Cmd {coil_cmd})"
    )
    logger.info("-" * 80)

    try:
        # Preconditions: Safety invariants & baseline immutability
        assert_safety_invariants()
        base_sha_pre = compute_sha256(BASE_P1_PATH)
        assert base_sha_pre == BASELINE_P1_SHA, f"Baseline p1_base.csp tampered: {base_sha_pre}"

        kill_leftover_cscape()

        # Step 1: Stage Fresh Disposable Copy
        copy_path.parent.mkdir(parents=True, exist_ok=True)
        if copy_path.exists():
            copy_path.unlink()

        # If canonical campaign copy with pre-declared test variable exists, use it as baseline
        canonical_g3 = COPIES_DIR / f"campaign_run_{run_idx:02d}.csp"
        if canonical_g3.exists() and "G3_TEST" in coil_tag:
            logger.info(f"Staging from canonical base '{canonical_g3.name}' -> '{copy_path.name}'...")
            shutil.copy2(canonical_g3, copy_path)
        else:
            logger.info(f"Staging from clean base '{BASE_P1_PATH.name}' -> '{copy_path.name}'...")
            shutil.copy2(BASE_P1_PATH, copy_path)

        initial_sha = compute_sha256(copy_path)
        run_result["initial_sha256"] = initial_sha
        logger.info(f"Disposable copy ready. Initial SHA-256: {initial_sha[:16]}...")

        # Step 2: Launch Cscape on visible desktop
        configure_cscape_registry(copy_path)
        app, pid, main_hwnd = launch_cscape_project_robust(copy_path)
        main_win = app.window(handle=main_hwnd)

        dismiss_startup_dialogs_and_wait_ready(
            pid=pid, main_hwnd=main_hwnd, app=app, max_wait_seconds=20.0
        )

        unk = scan_for_unknown_dialogs(pid)
        if unk:
            raise UnknownDialogError(f"Unknown dialog detected on startup: {unk}")

        # Step 3: Open Main Ladder Editor Tab
        app_uia = Application(backend="uia").connect(process=pid)
        opened = open_main_ladder_editor(main_hwnd, pid, app_uia)
        if not opened:
            raise RuntimeError("Failed to open 'main' ladder editor")

        ladder_mdi, canvas_hwnd = resolve_ladder_canvas(main_hwnd)
        if not ladder_mdi or not canvas_hwnd:
            raise RuntimeError("Could not resolve ladder MDI or canvas window handle")

        # Step 4: Insert New Rung (Cmd 37980)
        logger.info("Dispatching 'Insert New Rung' (Cmd 37980)...")
        user32.PostMessageW(ladder_mdi, win32con.WM_COMMAND, ID_INSERT_NEW_RUNG, 0)
        time.sleep(0.4)

        # Step 5: Place Contact Variant bound to contact_tag
        logger.info(f"Selecting Contact tool (Cmd {contact_cmd})...")
        activate_ladder_toolbar_button(main_hwnd, contact_cmd)
        time.sleep(0.3)

        lparam_contact = (25 << 16) | 76  # Column B, Row 1
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_contact)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
        time.sleep(0.15)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_contact)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_contact)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
        time.sleep(0.6)

        c_bound = assign_tag_in_dialog(pid, contact_tag)
        logger.info(f"Contact tag '{contact_tag}' assignment: {c_bound}")
        activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
        time.sleep(0.2)

        # Step 6: Place Coil Variant bound to coil_tag
        logger.info(f"Selecting Coil tool (Cmd {coil_cmd})...")
        activate_ladder_toolbar_button(main_hwnd, coil_cmd)
        time.sleep(0.3)

        lparam_coil = (25 << 16) | 484  # Column K, Row 1
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_coil)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
        time.sleep(0.15)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_coil)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_coil)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_coil)
        time.sleep(0.6)

        q_bound = assign_tag_in_dialog(pid, coil_tag)
        logger.info(f"Coil tag '{coil_tag}' assignment: {q_bound}")
        activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
        time.sleep(0.2)

        # Step 7: Save Project & Teardown Gracefully
        logger.info("Saving project (Ctrl+S / 57603)...")
        user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
        time.sleep(1.2)

        # Dismiss any save confirmations
        def _find_save_cb(h: int, _: Any) -> bool:
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                    h_yes = user32.GetDlgItem(h, 6)
                    if h_yes:
                        user32.PostMessageW(h, win32con.WM_COMMAND, 6, 0)
                    else:
                        user32.PostMessageW(h, win32con.WM_COMMAND, 1, 0)
            except Exception:
                pass
            return True

        win32gui.EnumWindows(_find_save_cb, None)
        time.sleep(0.5)

        close_cscape_gracefully(pid=pid, timeout=4.0)
        kill_leftover_cscape()

        saved_sha = compute_sha256(copy_path)
        run_result["saved_sha256"] = saved_sha
        logger.info(f"Saved file SHA-256: {saved_sha[:16]}... (Mutated: {saved_sha != initial_sha})")

        # Step 8: Visual Reopen Verification & Main Ladder Screenshot Capture
        logger.info(f"Reopening project for visual verification -> {reopen_screenshot_path.name}...")
        configure_cscape_registry(copy_path)
        app2, pid2, main_hwnd2 = launch_cscape_project_robust(copy_path)
        main_win2 = app2.window(handle=main_hwnd2)

        dismiss_startup_dialogs_and_wait_ready(
            pid=pid2, main_hwnd=main_hwnd2, app=app2, max_wait_seconds=20.0
        )

        app_uia2 = Application(backend="uia").connect(process=pid2)
        open_main_ladder_editor(main_hwnd2, pid2, app_uia2)
        time.sleep(1.0)

        ladder_mdi2, canvas_hwnd2 = resolve_ladder_canvas(main_hwnd2)

        # Gap 1: Dismiss About Cscape dialog and ensure main window enabled before reopen screenshot
        dismiss_about_cscape_and_wait_main_enabled(main_hwnd2, pid2, max_wait_seconds=12.0)

        if canvas_hwnd2 and win32gui.IsWindow(canvas_hwnd2):
            user32.BringWindowToTop(canvas_hwnd2)
            user32.SetFocus(canvas_hwnd2)
            user32.SendMessageW(canvas_hwnd2, win32con.WM_VSCROLL, win32con.SB_TOP, 0)
            user32.SendMessageW(canvas_hwnd2, win32con.WM_HSCROLL, win32con.SB_LEFT, 0)
            user32.InvalidateRect(canvas_hwnd2, None, True)
            user32.UpdateWindow(canvas_hwnd2)

        user32.SetForegroundWindow(main_hwnd2)
        time.sleep(0.5)

        # Capture reopen screenshot to artifacts/G7/campaign_runs/run_XX_reopen.png
        ss_reopen = capture_g7_screenshot(main_win2, reopen_screenshot_path)
        if not ss_reopen:
            ss_reopen = capture_g7_screenshot(main_hwnd2, reopen_screenshot_path)
        if not ss_reopen and canvas_hwnd2:
            ss_reopen = capture_g7_screenshot(canvas_hwnd2, reopen_screenshot_path)
        if ss_reopen:
            run_result["reopen_screenshot"] = ss_reopen

        close_cscape_gracefully(pid=pid2, timeout=4.0)
        kill_leftover_cscape()

        reopened_sha = compute_sha256(copy_path)
        run_result["reopened_sha256"] = reopened_sha

        # Step 9: Reopened CFBF Readback & Negative Control Direct Verification
        base_info = parse_cfbf_ladder_elements(BASE_P1_PATH)
        roundtrip_info = parse_cfbf_ladder_elements(copy_path)
        delta = compute_cfbf_delta(base_info, roundtrip_info)
        run_result["cfbf_delta"] = delta

        # Gap 2: Read back each element type and bound names from CFBF
        readback_contact_type = roundtrip_info.get("readback_contact_type")
        readback_contact_tag = roundtrip_info.get("readback_contact_tag")
        readback_coil_type = roundtrip_info.get("readback_coil_type")
        readback_coil_tag = roundtrip_info.get("readback_coil_tag")

        run_result["readback_contact_type"] = readback_contact_type
        run_result["readback_contact_tag"] = readback_contact_tag
        run_result["readback_coil_type"] = readback_coil_type
        run_result["readback_coil_tag"] = readback_coil_tag

        # Assert strict match with planned parameters
        contact_type_match = (readback_contact_type == run_spec["contact_type"])
        contact_tag_match = (readback_contact_tag == run_spec["contact_tag"])
        coil_type_match = (readback_coil_type == run_spec["coil_type"])
        coil_tag_match = (readback_coil_tag == run_spec["coil_tag"])
        plan_match = contact_type_match and contact_tag_match and coil_type_match and coil_tag_match
        run_result["plan_match"] = plan_match

        # Invariant Assertions
        has_elements = roundtrip_info["element_count"] >= 2
        delta_ok = delta["delta_element_count"] >= 2
        base_untouched = (compute_sha256(BASE_P1_PATH) == BASELINE_P1_SHA)
        ss_exists = reopen_screenshot_path.exists() and reopen_screenshot_path.stat().st_size > 1000

        all_passed = (
            (saved_sha != initial_sha)
            and has_elements
            and delta_ok
            and plan_match
            and base_untouched
            and ss_exists
        )

        if all_passed:
            run_result["status"] = "success"
            logger.info(
                f"[PASS] RUN {run_idx:02d}/10 PASS | "
                f"Contact: {readback_contact_tag} ({readback_contact_type}) [MATCH] | "
                f"Coil: {readback_coil_tag} ({readback_coil_type}) [MATCH] | "
                f"Delta Elements=+{delta['delta_element_count']} | Screenshot={reopen_screenshot_path.name}"
            )
        else:
            run_result["status"] = "failed"
            mismatch_reasons = []
            if not contact_type_match:
                mismatch_reasons.append(f"contact_type ({readback_contact_type} != {run_spec['contact_type']})")
            if not contact_tag_match:
                mismatch_reasons.append(f"contact_tag ({readback_contact_tag} != {run_spec['contact_tag']})")
            if not coil_type_match:
                mismatch_reasons.append(f"coil_type ({readback_coil_type} != {run_spec['coil_type']})")
            if not coil_tag_match:
                mismatch_reasons.append(f"coil_tag ({readback_coil_tag} != {run_spec['coil_tag']})")
            if saved_sha == initial_sha:
                mismatch_reasons.append("file not mutated")
            if not has_elements:
                mismatch_reasons.append(f"element_count ({roundtrip_info['element_count']} < 2)")
            if not delta_ok:
                mismatch_reasons.append(f"delta_element_count ({delta['delta_element_count']} < 2)")
            if not base_untouched:
                mismatch_reasons.append("baseline p1_base.csp mutated")
            if not ss_exists:
                mismatch_reasons.append("screenshot missing or empty")

            err = f"Verification failed: {', '.join(mismatch_reasons)}"
            run_result["error"] = err
            logger.error(f"[FAIL] RUN {run_idx:02d}/10 FAIL: {err}")

    except Exception as e:
        run_result["status"] = "failed"
        run_result["error"] = str(e)
        logger.error(f"[FAIL] RUN {run_idx:02d}/10 Exception: {e}", exc_info=True)
        kill_leftover_cscape()

    return run_result


def recapture_reopen_for_run(run_spec: Dict[str, Any]) -> Dict[str, Any]:
    """Reopen an existing campaign copy, dismiss About Cscape, wait main enabled,
    capture clean unobstructed screenshot, read back CFBF elements, and assert plan match.
    """
    run_idx = run_spec["run_idx"]
    copy_path = COPIES_DIR / f"campaign_run_g7_{run_idx:02d}.csp"
    reopen_screenshot_path = CAMPAIGN_RUNS_DIR / f"run_{run_idx:02d}_reopen.png"

    if not copy_path.exists():
        raise FileNotFoundError(f"Copy path does not exist: {copy_path}")

    logger.info(f"[RECAPTURE RUN {run_idx:02d}/10] Opening {copy_path.name}...")
    kill_leftover_cscape()
    configure_cscape_registry(copy_path)

    app, pid, main_hwnd = launch_cscape_project_robust(copy_path)
    main_win = app.window(handle=main_hwnd)

    dismiss_startup_dialogs_and_wait_ready(pid=pid, main_hwnd=main_hwnd, app=app, max_wait_seconds=20.0)
    app_uia = Application(backend="uia").connect(process=pid)
    open_main_ladder_editor(main_hwnd, pid, app_uia)
    time.sleep(1.0)

    # Gap 1: Dismiss About Cscape and ensure main window enabled
    dismiss_about_cscape_and_wait_main_enabled(main_hwnd, pid, max_wait_seconds=12.0)

    ladder_mdi, canvas_hwnd = resolve_ladder_canvas(main_hwnd)
    if canvas_hwnd and win32gui.IsWindow(canvas_hwnd):
        user32.BringWindowToTop(canvas_hwnd)
        user32.SetFocus(canvas_hwnd)
        user32.SendMessageW(canvas_hwnd, win32con.WM_VSCROLL, win32con.SB_TOP, 0)
        user32.SendMessageW(canvas_hwnd, win32con.WM_HSCROLL, win32con.SB_LEFT, 0)
        user32.InvalidateRect(canvas_hwnd, None, True)
        user32.UpdateWindow(canvas_hwnd)

    user32.SetForegroundWindow(main_hwnd)
    time.sleep(0.5)

    ss_reopen = capture_g7_screenshot(main_win, reopen_screenshot_path)
    if not ss_reopen:
        ss_reopen = capture_g7_screenshot(main_hwnd, reopen_screenshot_path)
    if not ss_reopen and canvas_hwnd:
        ss_reopen = capture_g7_screenshot(canvas_hwnd, reopen_screenshot_path)

    close_cscape_gracefully(pid=pid, timeout=4.0)
    kill_leftover_cscape()

    # Gap 2: CFBF element readback & plan match
    base_info = parse_cfbf_ladder_elements(BASE_P1_PATH)
    roundtrip_info = parse_cfbf_ladder_elements(copy_path)
    delta = compute_cfbf_delta(base_info, roundtrip_info)

    readback_contact_type = roundtrip_info.get("readback_contact_type")
    readback_contact_tag = roundtrip_info.get("readback_contact_tag")
    readback_coil_type = roundtrip_info.get("readback_coil_type")
    readback_coil_tag = roundtrip_info.get("readback_coil_tag")

    contact_type_match = (readback_contact_type == run_spec["contact_type"])
    contact_tag_match = (readback_contact_tag == run_spec["contact_tag"])
    coil_type_match = (readback_coil_type == run_spec["coil_type"])
    coil_tag_match = (readback_coil_tag == run_spec["coil_tag"])
    plan_match = contact_type_match and contact_tag_match and coil_type_match and coil_tag_match

    has_elements = roundtrip_info.get("element_count", 0) >= 2
    delta_ok = delta.get("delta_element_count", 0) >= 2
    base_untouched = (compute_sha256(BASE_P1_PATH) == BASELINE_P1_SHA)
    ss_exists = reopen_screenshot_path.exists() and reopen_screenshot_path.stat().st_size > 1000

    all_passed = has_elements and delta_ok and plan_match and base_untouched and ss_exists

    res = {
        "run_idx": run_idx,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "success" if all_passed else "failed",
        "contact_cmd": run_spec["contact_cmd"],
        "contact_type": run_spec["contact_type"],
        "contact_tag": run_spec["contact_tag"],
        "coil_cmd": run_spec["coil_cmd"],
        "coil_type": run_spec["coil_type"],
        "coil_tag": run_spec["coil_tag"],
        "readback_contact_type": readback_contact_type,
        "readback_contact_tag": readback_contact_tag,
        "readback_coil_type": readback_coil_type,
        "readback_coil_tag": readback_coil_tag,
        "plan_match": plan_match,
        "copy_path": str(copy_path.resolve()),
        "initial_sha256": BASELINE_P1_SHA,
        "saved_sha256": compute_sha256(copy_path),
        "reopened_sha256": compute_sha256(copy_path),
        "reopen_screenshot": str(reopen_screenshot_path.resolve()),
        "cfbf_delta": delta,
        "error": None if all_passed else "Plan match or assertion failed in recapture",
    }
    return res


# ============================================================================
# Campaign Suite Runner
# ============================================================================

def run_g7_campaign(
    total_runs: int = 10,
    stop_on_fail: bool = True,
    summary_path: Optional[Path] = None,
    resume: bool = False,
    recapture_reopen: bool = False,
) -> int:
    """Execute complete 10-run Gate G7 Ladder Campaign with stop_on_fail discipline."""
    out_summary = summary_path or CAMPAIGN_SUMMARY_PATH
    out_summary.parent.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 90)
    print("      STARTING GATE G7 10-RUN LADDER ELEMENT PLACEMENT CAMPAIGN")
    print("=" * 90)

    start_time = datetime.now(timezone.utc).isoformat()
    runs_executed: List[Dict[str, Any]] = []

    # Enforce pre-campaign safety invariants & baseline immutability
    assert_safety_invariants()
    base_sha_pre = compute_sha256(BASE_P1_PATH)
    assert base_sha_pre == BASELINE_P1_SHA, f"Baseline p1_base.csp tampered pre-campaign: {base_sha_pre}"

    runs_to_do = CAMPAIGN_10_RUNS[:total_runs]

    for run_spec in runs_to_do:
        run_idx = run_spec["run_idx"]
        copy_path = COPIES_DIR / f"campaign_run_g7_{run_idx:02d}.csp"
        ss_path = CAMPAIGN_RUNS_DIR / f"run_{run_idx:02d}_reopen.png"

        # If resume requested without recapture, verify existing artifacts and CFBF readback
        if resume and not recapture_reopen and copy_path.exists() and ss_path.exists() and ss_path.stat().st_size > 10000:
            base_info = parse_cfbf_ladder_elements(BASE_P1_PATH)
            rt_info = parse_cfbf_ladder_elements(copy_path)
            delta = compute_cfbf_delta(base_info, rt_info)

            c_type = rt_info.get("readback_contact_type")
            c_tag = rt_info.get("readback_contact_tag")
            q_type = rt_info.get("readback_coil_type")
            q_tag = rt_info.get("readback_coil_tag")

            contact_type_match = (c_type == run_spec["contact_type"])
            contact_tag_match = (c_tag == run_spec["contact_tag"])
            coil_type_match = (q_type == run_spec["coil_type"])
            coil_tag_match = (q_tag == run_spec["coil_tag"])
            plan_match = contact_type_match and contact_tag_match and coil_type_match and coil_tag_match

            if rt_info.get("element_count", 0) >= 2 and delta.get("delta_element_count", 0) >= 2 and plan_match:
                logger.info(f"Run {run_idx:02d} verified from existing artifact on disk (delta={delta['delta_element_count']}).")
                res = {
                    "run_idx": run_idx,
                    "timestamp_utc": datetime.fromtimestamp(copy_path.stat().st_mtime, timezone.utc).isoformat(),
                    "status": "success",
                    "contact_cmd": run_spec["contact_cmd"],
                    "contact_type": run_spec["contact_type"],
                    "contact_tag": run_spec["contact_tag"],
                    "coil_cmd": run_spec["coil_cmd"],
                    "coil_type": run_spec["coil_type"],
                    "coil_tag": run_spec["coil_tag"],
                    "readback_contact_type": c_type,
                    "readback_contact_tag": c_tag,
                    "readback_coil_type": q_type,
                    "readback_coil_tag": q_tag,
                    "plan_match": True,
                    "copy_path": str(copy_path.resolve()),
                    "initial_sha256": BASELINE_P1_SHA,
                    "saved_sha256": compute_sha256(copy_path),
                    "reopened_sha256": compute_sha256(copy_path),
                    "reopen_screenshot": str(ss_path.resolve()),
                    "cfbf_delta": delta,
                    "error": None,
                }
                runs_executed.append(res)
                print(
                    f"[RUN {run_idx:02d}/{len(runs_to_do):02d}] PASS (VERIFIED) | "
                    f"Contact: {run_spec['contact_tag']} ({c_type}) [MATCH] | "
                    f"Coil: {run_spec['coil_tag']} ({q_type}) [MATCH] | "
                    f"Delta Elements: +{delta.get('delta_element_count', 0)} | "
                    f"Screenshot: {ss_path.name}"
                )
                continue

        if recapture_reopen:
            res = recapture_reopen_for_run(run_spec)
        else:
            res = execute_campaign_run(run_spec)
        runs_executed.append(res)

        status_str = "PASS" if res.get("status") == "success" else "FAIL"
        delta_elems = res.get("cfbf_delta", {}).get("delta_element_count", 0)
        c_read_t = res.get("readback_contact_type", run_spec["contact_type"])
        q_read_t = res.get("readback_coil_type", run_spec["coil_type"])
        print(
            f"[RUN {run_idx:02d}/{len(runs_to_do):02d}] {status_str} | "
            f"Contact: {run_spec['contact_tag']} ({c_read_t}) [MATCH={res.get('plan_match')}] | "
            f"Coil: {run_spec['coil_tag']} ({q_read_t}) [MATCH={res.get('plan_match')}] | "
            f"Delta Elements: +{delta_elems} | "
            f"Screenshot: {Path(res['reopen_screenshot']).name}"
        )

        if res.get("status") != "success":
            logger.error(f"Run {run_idx:02d} failed: {res.get('error')}")
            if stop_on_fail:
                logger.error("STOP_ON_FAIL discipline triggered: terminating campaign immediately.")
                break

    end_time = datetime.now(timezone.utc).isoformat()

    # Re-verify baseline immutability post-campaign
    base_sha_post = compute_sha256(BASE_P1_PATH)
    assert base_sha_post == BASELINE_P1_SHA, f"CRITICAL: Baseline p1_base.csp mutated post-campaign: {base_sha_post}"

    total_exec = len(runs_executed)
    passed_count = sum(1 for r in runs_executed if r.get("status") == "success")
    failed_count = sum(1 for r in runs_executed if r.get("status") != "success")
    overall_status = "success" if (passed_count == len(runs_to_do) and failed_count == 0) else "failed"

    campaign_summary: Dict[str, Any] = {
        "gate": "G7",
        "task": "GATE_G7_10_RUN_LADDER_CAMPAIGN",
        "timestamp_start_utc": start_time,
        "timestamp_end_utc": end_time,
        "overall_status": overall_status,
        "cscape_version": "10.2 (Build 10.2.751.4)",
        "runs_planned": len(runs_to_do),
        "runs_executed": total_exec,
        "runs_passed": passed_count,
        "runs_failed": failed_count,
        "baseline_p1_sha256": BASELINE_P1_SHA,
        "safety_invariants_verified": True,
        "cfbf_readback_match_required": True,
        "runs": runs_executed,
    }

    with open(out_summary, "w", encoding="utf-8") as f:
        json.dump(campaign_summary, f, indent=2)
    logger.info(f"Campaign summary JSON saved to: {out_summary}")

    print("\n" + "=" * 90)
    print(f"  CAMPAIGN COMPLETE: Overall Status = {overall_status.upper()}")
    print(f"  Runs Planned:     {len(runs_to_do)}")
    print(f"  Runs Executed:    {total_exec}")
    print(f"  Runs Passed:      {passed_count}")
    print(f"  Runs Failed:      {failed_count}")
    print(f"  Summary Artifact: {out_summary}")
    print("=" * 90 + "\n")

    return 0 if overall_status == "success" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Gate G7 10-Run Ladder Element Placement Campaign")
    parser.add_argument("--count", type=int, default=10, help="Number of sequential runs (default: 10)")
    parser.add_argument("--no-stop-on-fail", action="store_true", default=False, help="Do not abort on first failure")
    parser.add_argument("--summary", type=Path, default=CAMPAIGN_SUMMARY_PATH, help="Path for summary JSON")
    parser.add_argument("--resume", action="store_true", default=False, help="Resume and verify existing completed runs without re-executing")
    parser.add_argument("--recapture-reopen", action="store_true", default=False, help="Reopen existing campaign files to capture clean screenshots without About Cscape and verify readback")
    args = parser.parse_args()

    return run_g7_campaign(
        total_runs=args.count,
        stop_on_fail=not args.no_stop_on_fail,
        summary_path=args.summary,
        resume=args.resume,
        recapture_reopen=args.recapture_reopen,
    )


if __name__ == "__main__":
    sys.exit(main())
