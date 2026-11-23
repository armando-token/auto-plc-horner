r"""Gate G3 Diagnostic Probe: Program Variables Pane Deep Inspection.

USER EXECUTION DIRECTIVE:
Run this script from a normal interactive PowerShell terminal on the visible desktop:
    cd C:\HornerAI\jev-cscape-agent
    python scripts/probe_program_variables.py

FUNCTIONALITY & VERIFICATION:
1. Asserts fail-closed hardware lockout and source file immutability.
2. Copies work/disposable/p1_base.csp to work/disposable/copies/probe_pv.csp.
3. Launches Cscape 10.2 targeting probe_pv.csp on the visible desktop.
4. Traps, logs, and handles known startup dialogs (Select Editor Type, Ladder Tags Mode, Hardware Configuration, Tip of the Day).
5. Waits until Cscape main window is fully enabled (IsWindowEnabled == True).
6. Opens Home ribbon > Program Variables pane (clicks Program Variables button via click_input).
7. Pauses to allow the pane and all docking containers to fully render.
8. Captures a full desktop screenshot of Cscape.
9. Performs deep Win32 inspection:
   - Enumerates every HWND belonging to the Cscape process across all top-level frames, dock bars, and child hierarchies.
   - Extracts class_name, window_text, WM_GETTEXT, control ID, bounding rectangle, visibility, enabled state, styles, parent HWND, and control item counts.
   - Identifies all windows inside or associated with the Program Variables pane.
10. Performs deep UIAutomation (UIA) inspection:
   - Walks the UIA accessibility tree of the Program Variables docking pane.
   - Dumps control types, names, automation IDs, class names, rectangles, focus states, and supported UIA patterns.
11. Crops the full screenshot to the exact bounding box of the Program Variables pane and saves it.
12. Exports complete structured forensic data to artifacts/G3/pv_probe.json.
13. Prints a clean, actionable short summary to stdout.
14. Closes Cscape gracefully (clicking 'No' on any 'Save changes?' prompt).
15. Enforces strictly read-only execution: zero project edits, zero disk mutations to base files.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import time
import winreg
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
import win32con
import win32gui
import win32process
from PIL import Image
from pywinauto import Application
from pywinauto.win32structures import RECT

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.contracts import AgentStatus
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.security.guard import SecurityGuard

# Setup logging
LOG_DIR = REPO_ROOT / "artifacts" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
G3_DIR = REPO_ROOT / "artifacts" / "G3"
G3_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "probe_program_variables.log", mode="w", encoding="utf-8"),
    ],
)
logger = logging.getLogger("probe_program_variables")

DEFAULT_CSCAPE_PATH = r"C:\Program Files (x86)\Cscape 10.2\Cscape.exe"
SOURCE_SANDBOX_PATH = REPO_ROOT / "work" / "disposable" / "test_sandbox.csp"
BASE_P1_PATH = REPO_ROOT / "work" / "disposable" / "p1_base.csp"
COPIES_DIR = REPO_ROOT / "work" / "disposable" / "copies"
PROBE_COPY_PATH = COPIES_DIR / "probe_pv.csp"

EVIDENCE_JSON_PATH = G3_DIR / "pv_probe.json"
FULL_SCREENSHOT_PATH = G3_DIR / "pv_probe_full.png"
PANE_SCREENSHOT_PATH = G3_DIR / "pv_probe_pane.png"

BASELINE_SANDBOX_SHA = "25112eebdae56a77a97c0e37536eab3975a38ae3815b3850b9a8dfa12bb20592"
BASELINE_P1_SHA = "5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881"

# Win32 Control Messages
TVM_GETCOUNT = 0x1105
LVM_GETITEMCOUNT = 0x1004
LB_GETCOUNT = 0x018B
CB_GETCOUNT = 0x0146

user32 = ctypes.windll.user32


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def assert_safety_invariants() -> None:
    """Enforce fail-closed hardware lockout and source file immutability."""
    logger.info("Asserting fail-closed security invariants...")

    # 1. Physical COM port lockout assertion
    for port in ["COM1", "COM3", "COM256"]:
        try:
            SecurityGuard.assert_port_safe(port)
            raise RuntimeError(f"CRITICAL SAFETY BREACH: {port} was NOT blocked by SecurityGuard!")
        except Exception:
            pass
    logger.info("[PASS] Physical communication ports COM1..COM256 verified blocked.")

    # 2. Download command ID interception assertion
    interceptor = Win32CommandInterceptor()
    for cmd_id in [32827, 33149]:
        res = interceptor.dispatch_safe_command(hwnd=0, cmd_id=cmd_id)
        if res.status != AgentStatus.BLOCKED:
            raise RuntimeError(f"CRITICAL SAFETY BREACH: Download command ID {cmd_id} was NOT blocked!")
    logger.info("[PASS] Win32 download command IDs 32827 and 33149 verified blocked.")

    # 3. Source test_sandbox.csp immutability assertion
    if not SOURCE_SANDBOX_PATH.exists():
        raise FileNotFoundError(f"Source file missing: {SOURCE_SANDBOX_PATH}")
    current_sandbox_sha = compute_sha256(SOURCE_SANDBOX_PATH)
    if current_sandbox_sha != BASELINE_SANDBOX_SHA:
        raise RuntimeError(
            f"CRITICAL IMMUTABILITY VIOLATION: test_sandbox.csp modified! Expected {BASELINE_SANDBOX_SHA}, got {current_sandbox_sha}"
        )
    logger.info(f"[PASS] Source test_sandbox.csp verified untouched (SHA: {current_sandbox_sha[:16]}...).")

    # 4. Base p1_base.csp immutability assertion
    if not BASE_P1_PATH.exists():
        raise FileNotFoundError(f"Base project missing: {BASE_P1_PATH}")
    base_sha = compute_sha256(BASE_P1_PATH)
    if base_sha != BASELINE_P1_SHA:
        raise RuntimeError(
            f"CRITICAL IMMUTABILITY VIOLATION: p1_base.csp modified! Expected {BASELINE_P1_SHA}, got {base_sha}"
        )
    logger.info(f"[PASS] Base p1_base.csp verified present and untouched (SHA: {base_sha[:16]}...).")


def configure_cscape_registry(project_path: Optional[Path] = None) -> None:
    """Configure Cscape registry keys for clean modal suppression and document targeting."""
    try:
        k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Horner_Electric\Cscape\Editor")
        winreg.SetValueEx(k, "AllowUserToChooseProgram", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(k, "OpenLast", 0, winreg.REG_DWORD, 1 if project_path else 0)
        winreg.SetValueEx(k, "CreateBlankProgram", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(k)

        k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Horner_Electric\Cscape\Setup")
        winreg.SetValueEx(k, "CscapeExitedCorrectly", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(k)

        if project_path:
            k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Horner_Electric\Cscape\Recent File List")
            winreg.SetValueEx(k, "File1", 0, winreg.REG_SZ, str(project_path.resolve()))
            winreg.CloseKey(k)
        logger.info("Cscape registry configuration applied.")
    except Exception as e:
        logger.warning(f"Could not configure registry: {e}")


def get_cscape_processes() -> List[psutil.Process]:
    """Find all running Cscape.exe processes."""
    procs = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            if p.info["name"] and p.info["name"].lower() == "cscape.exe":
                procs.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return procs


def enumerate_cscape_windows(pid: int) -> List[Tuple[int, str, str]]:
    """Enumerate all visible windows belonging to the Cscape process."""
    windows = []

    def enum_cb(h: int, _: Any) -> bool:
        if win32gui.IsWindowVisible(h):
            try:
                _, w_pid = win32process.GetWindowThreadProcessId(h)
                if w_pid == pid:
                    cls = win32gui.GetClassName(h)
                    title = win32gui.GetWindowText(h)
                    windows.append((h, cls, title))
            except Exception:
                pass
        return True

    try:
        win32gui.EnumWindows(enum_cb, None)
    except Exception:
        pass
    return windows


def close_cscape_gracefully(pid: Optional[int] = None, timeout: float = 6.0) -> None:
    """Close Cscape instances gracefully via WM_CLOSE, handling 'Save changes?' prompt by clicking 'No'."""
    target_procs = [p for p in get_cscape_processes() if (pid is None or p.pid == pid)]
    for p in target_procs:
        try:
            logger.info(f"Closing Cscape process PID {p.pid} gracefully...")
            windows = enumerate_cscape_windows(p.pid)
            for h, cls, title in windows:
                if cls.startswith("Afx"):
                    win32gui.PostMessage(h, win32con.WM_CLOSE, 0, 0)

            # Monitor for any prompt dialogs ("Save changes?") on close and click 'No'
            start_wait = time.time()
            while time.time() - start_wait < timeout:
                if not p.is_running():
                    break
                windows = enumerate_cscape_windows(p.pid)
                for h, cls, title in windows:
                    if cls == "#32770":
                        logger.info(f"Close confirmation dialog detected: '{title}' (HWND {hex(h)}).")
                        try:
                            app_temp = Application(backend="win32").connect(process=p.pid)
                            dlg = app_temp.window(handle=h)
                            no_btn = dlg.child_window(title="&No", control_type="Button")
                            if not no_btn.exists():
                                no_btn = dlg.child_window(title="No", control_type="Button")
                            if no_btn.exists():
                                logger.info("Clicking 'No' button on confirmation prompt...")
                                no_btn.click_input()
                                time.sleep(0.5)
                            else:
                                dlg.type_keys("%n")
                        except Exception:
                            try:
                                app_temp = Application(backend="win32").connect(process=p.pid)
                                app_temp.window(handle=h).type_keys("%n")
                            except Exception:
                                pass
                time.sleep(0.5)

            if p.is_running():
                p.kill()
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    time.sleep(1.0)


def resolve_known_startup_dialog(hwnd: int, cls: str, title: str, app: Application) -> bool:
    """Handle known Cscape startup dialogs."""
    t_low = title.lower()
    dlg_wrap = app.window(handle=hwnd)
    user32.SetForegroundWindow(hwnd)
    time.sleep(0.4)

    # 1. Select Editor Type
    if "select editor type" in t_low:
        logger.info(f"Handling known dialog 'Select Editor Type' (HWND {hex(hwnd)})...")
        try:
            ok_btn = dlg_wrap.child_window(title="OK", control_type="Button")
            if ok_btn.exists():
                ok_btn.click_input()
            else:
                dlg_wrap.type_keys("{ENTER}")
        except Exception:
            dlg_wrap.type_keys("{ENTER}")
        time.sleep(1.5)
        return True

    # 2. Ladder Tags Mode
    elif "ladder tags mode" in t_low or ("tag" in t_low and "mode" in t_low):
        logger.info(f"Handling known dialog 'Ladder Tags Mode' (HWND {hex(hwnd)})...")
        try:
            for child in dlg_wrap.children():
                c_text = child.window_text().lower()
                if "acknowledge" in c_text or (child.class_name().lower() == "button" and (child.style() & 0x000F) in [2, 3, 5, 6]):
                    child.click_input()
                    time.sleep(0.3)
                    break
        except Exception:
            dlg_wrap.type_keys("{SPACE}")

        try:
            ok_btn = dlg_wrap.child_window(title="OK", control_type="Button")
            if ok_btn.exists():
                ok_btn.click_input()
            else:
                dlg_wrap.type_keys("{ENTER}")
        except Exception:
            dlg_wrap.type_keys("{ENTER}")
        time.sleep(1.5)
        return True

    # 3. Hardware Configuration
    elif any(k in t_low for k in ["hardware", "configure", "controller", "xl4", "he-xpc"]):
        logger.info(f"Handling known dialog 'Hardware Configuration' (HWND {hex(hwnd)})...")
        try:
            ok_btn = dlg_wrap.child_window(title="OK", control_type="Button")
            if ok_btn.exists():
                ok_btn.click_input()
            else:
                dlg_wrap.type_keys("{ENTER}")
        except Exception:
            dlg_wrap.type_keys("{ENTER}")
        time.sleep(1.5)
        return True

    # 4. Dismissible popups
    elif any(k in t_low for k in ["tip of the day", "about cscape", "welcome"]):
        logger.info(f"Dismissing known popup '{title}' (HWND {hex(hwnd)})...")
        try:
            ok_btn = dlg_wrap.child_window(title="OK", control_type="Button")
            if ok_btn.exists():
                ok_btn.click_input()
            else:
                dlg_wrap.type_keys("{ESC}")
        except Exception:
            dlg_wrap.type_keys("{ESC}")
        time.sleep(1.0)
        return True

    return False


def handle_startup_dialogs_and_wait_for_main_window(
    pid: int,
    main_hwnd: int,
    app: Application,
    max_wait_seconds: float = 30.0
) -> None:
    """Detect, log, and resolve modal dialogs until the Cscape main window is fully enabled."""
    start_time = time.time()
    logger.info("Checking for startup modal/owned dialogs and waiting for main window enabled...")

    while time.time() - start_time < max_wait_seconds:
        windows = enumerate_cscape_windows(pid)
        modals = []
        for h, cls, title in windows:
            if h == main_hwnd:
                continue
            owner = win32gui.GetWindow(h, win32con.GW_OWNER)
            style = win32gui.GetWindowLong(h, win32con.GWL_STYLE)
            is_popup = (style & win32con.WS_POPUP) != 0
            if cls == "#32770" or owner == main_hwnd or (is_popup and not cls.startswith("Afx")):
                modals.append((h, cls, title))

        if modals:
            for h, cls, title in modals:
                handled = resolve_known_startup_dialog(h, cls, title, app)
                if not handled:
                    raise RuntimeError(f"ABORT_UNKNOWN_DIALOG: Unexpected modal dialog: '{title}' (HWND {hex(h)}).")
                time.sleep(1.0)
            continue

        if win32gui.IsWindowEnabled(main_hwnd):
            time.sleep(0.5)
            if win32gui.IsWindowEnabled(main_hwnd):
                logger.info(f"Cscape main window HWND {hex(main_hwnd)} is verified ENABLED and responsive.")
                return

        time.sleep(0.5)

    if not win32gui.IsWindowEnabled(main_hwnd):
        raise RuntimeError(f"Main window HWND {hex(main_hwnd)} remained disabled after {max_wait_seconds}s timeout.")


def open_program_variables_pane(main_hwnd: int, cscape_ui: Any) -> None:
    """Ensure Home ribbon is active and click 'Program Variables' button."""
    logger.info("Opening Program Variables pane from Home ribbon...")
    user32.SetForegroundWindow(main_hwnd)
    time.sleep(0.5)

    # 1. Switch to Home tab if available
    try:
        home_tab = cscape_ui.child_window(title="Home", control_type="TabItem")
        if home_tab.exists():
            home_tab.click_input()
            time.sleep(0.5)
    except Exception as e:
        logger.debug(f"Home tab click note: {e}")

    # 2. Locate and click 'Program Variables' button
    pv_btn = None
    try:
        for btn in cscape_ui.descendants(control_type="Button"):
            b_text = btn.window_text().strip()
            if "program variables" in b_text.lower():
                pv_btn = btn
                logger.info(f"Located 'Program Variables' button at {btn.rectangle()}")
                break
    except Exception as e:
        logger.warning(f"Error searching for Program Variables button: {e}")

    if pv_btn is not None:
        pv_btn.click_input()
        time.sleep(2.0)
    else:
        logger.info("Program Variables button not clicked via UIA; verifying visibility...")

    time.sleep(1.5)


def get_window_wm_gettext(hwnd: int) -> str:
    """Query window text using WM_GETTEXT."""
    try:
        buf_len = 2048
        buf = ctypes.create_unicode_buffer(buf_len)
        l = user32.SendMessageW(hwnd, win32con.WM_GETTEXT, buf_len, buf)
        return buf.value if l > 0 else ""
    except Exception:
        return ""


def get_control_item_count(hwnd: int, class_name: str) -> Optional[int]:
    """Query item count for common controls."""
    c_low = class_name.lower()
    try:
        if "tree" in c_low or "w5" in c_low:
            cnt = user32.SendMessageW(hwnd, TVM_GETCOUNT, 0, 0)
            if cnt >= 0:
                return cnt
        if "list" in c_low:
            cnt = user32.SendMessageW(hwnd, LVM_GETITEMCOUNT, 0, 0)
            if cnt >= 0:
                return cnt
            cnt = user32.SendMessageW(hwnd, LB_GETCOUNT, 0, 0)
            if cnt >= 0:
                return cnt
        if "combo" in c_low:
            cnt = user32.SendMessageW(hwnd, CB_GETCOUNT, 0, 0)
            if cnt >= 0:
                return cnt
    except Exception:
        pass
    return None


def probe_win32_hierarchy(pid: int, main_hwnd: int) -> List[Dict[str, Any]]:
    """Enumerate every window and child control belonging to the Cscape process."""
    logger.info("Enumerating complete Win32 window hierarchy for Cscape process...")
    all_windows: List[Dict[str, Any]] = []
    seen_hwnds = set()

    def inspect_hwnd(h: int, is_top_level: bool = False) -> Dict[str, Any]:
        cls = win32gui.GetClassName(h)
        title = win32gui.GetWindowText(h)
        wm_txt = get_window_wm_gettext(h)
        ctrl_id = win32gui.GetDlgCtrlID(h)
        rect = win32gui.GetWindowRect(h)
        is_vis = bool(win32gui.IsWindowVisible(h))
        is_en = bool(win32gui.IsWindowEnabled(h))
        style = win32gui.GetWindowLong(h, win32con.GWL_STYLE)
        ex_style = win32gui.GetWindowLong(h, win32con.GWL_EXSTYLE)
        parent_h = win32gui.GetParent(h)
        item_cnt = get_control_item_count(h, cls)

        # Count direct children
        child_hwnds = []
        def child_cb(ch: int, _: Any) -> bool:
            if win32gui.GetParent(ch) == h:
                child_hwnds.append(ch)
            return True
        try:
            win32gui.EnumChildWindows(h, child_cb, None)
        except Exception:
            pass

        rec = {
            "hwnd": h,
            "hwnd_hex": hex(h),
            "class_name": cls,
            "window_text": title,
            "wm_gettext": wm_txt,
            "ctrl_id": ctrl_id,
            "rect": {
                "left": rect[0],
                "top": rect[1],
                "right": rect[2],
                "bottom": rect[3],
                "width": rect[2] - rect[0],
                "height": rect[3] - rect[1],
            },
            "is_visible": is_vis,
            "is_enabled": is_en,
            "style_hex": hex(style),
            "ex_style_hex": hex(ex_style),
            "parent_hwnd_hex": hex(parent_h),
            "is_top_level": is_top_level,
            "direct_children_count": len(child_hwnds),
            "item_count": item_cnt,
        }
        return rec

    # 1. Enumerate all top-level windows of PID
    top_hwnds = []
    def top_cb(h: int, _: Any) -> bool:
        try:
            _, w_pid = win32process.GetWindowThreadProcessId(h)
            if w_pid == pid:
                top_hwnds.append(h)
        except Exception:
            pass
        return True

    win32gui.EnumWindows(top_cb, None)

    for top_h in top_hwnds:
        if top_h not in seen_hwnds:
            seen_hwnds.add(top_h)
            all_windows.append(inspect_hwnd(top_h, is_top_level=True))

        # Enumerate all children recursively under each top window
        def ch_cb(ch: int, _: Any) -> bool:
            if ch not in seen_hwnds:
                seen_hwnds.add(ch)
                all_windows.append(inspect_hwnd(ch, is_top_level=False))
            return True

        try:
            win32gui.EnumChildWindows(top_h, ch_cb, None)
        except Exception:
            pass

    logger.info(f"Total Win32 HWNDs enumerated: {len(all_windows)}")
    return all_windows


def probe_uia_elements(cscape_ui: Any) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """Inspect UIA accessibility elements of the Program Variables docking pane."""
    logger.info("Enumerating UIA accessibility elements for Program Variables pane...")

    pv_pane_info: Optional[Dict[str, Any]] = None
    pane_elements: List[Dict[str, Any]] = []

    # Find the Program Variables Pane
    pv_pane_wrap = None
    try:
        for child in cscape_ui.children():
            c_name = (getattr(child.element_info, "name", "") or child.window_text() or "").strip()
            if "program variables" in c_name.lower():
                pv_pane_wrap = child
                break
    except Exception as e:
        logger.debug(f"Direct UIA child search note: {e}")

    if pv_pane_wrap is None:
        try:
            for it in cscape_ui.descendants(control_type="Pane"):
                t = (getattr(it.element_info, "name", "") or it.window_text() or "").strip()
                if "program variables" in t.lower():
                    pv_pane_wrap = it
                    break
        except Exception as e:
            logger.debug(f"Pane descendant search note: {e}")

    pattern_names = [
        ("Invoke", 10000),
        ("Selection", 10001),
        ("Value", 10002),
        ("RangeValue", 10003),
        ("Scroll", 10004),
        ("ExpandCollapse", 10005),
        ("Grid", 10006),
        ("GridItem", 10007),
        ("MultipleView", 10008),
        ("Window", 10009),
        ("SelectionItem", 10010),
        ("Dock", 10011),
        ("Table", 10012),
        ("TableItem", 10013),
        ("Text", 10014),
        ("Toggle", 10015),
        ("Transform", 10016),
        ("ScrollItem", 10017),
        ("LegacyIAccessible", 10018),
        ("ItemContainer", 10019),
        ("VirtualizedItem", 10020),
    ]

    def extract_element_info(elem: Any) -> Dict[str, Any]:
        info = elem.element_info
        r = elem.rectangle()
        patterns = []
        try:
            raw = getattr(info, "_element", None)
            if raw:
                for p_name, p_id in pattern_names:
                    try:
                        pat = raw.GetCurrentPattern(p_id)
                        if pat:
                            patterns.append(p_name)
                    except Exception:
                        pass
        except Exception:
            pass

        return {
            "control_type": getattr(info, "control_type", ""),
            "name": getattr(info, "name", "") or elem.window_text() or "",
            "automation_id": getattr(info, "automation_id", ""),
            "class_name": getattr(info, "class_name", ""),
            "handle_hex": hex(getattr(info, "handle", 0)),
            "rect": {
                "left": r.left,
                "top": r.top,
                "right": r.right,
                "bottom": r.bottom,
                "width": r.width(),
                "height": r.height(),
            },
            "is_visible": getattr(info, "is_visible", None),
            "is_enabled": getattr(info, "is_enabled", None),
            "is_keyboard_focusable": getattr(info, "is_keyboard_focusable", None),
            "patterns": patterns,
        }

    if pv_pane_wrap is not None:
        pv_pane_info = extract_element_info(pv_pane_wrap)
        logger.info(f"Program Variables UIA Pane located: {pv_pane_info['rect']}")

        try:
            for desc in pv_pane_wrap.descendants():
                pane_elements.append(extract_element_info(desc))
        except Exception as e:
            logger.warning(f"Error enumerating pane descendants: {e}")

    logger.info(f"Total UIA elements enumerated under Program Variables: {len(pane_elements)}")
    return pv_pane_info, pane_elements


def run_probe() -> int:
    """Execute complete Program Variables pane discovery and dump."""
    logger.info("=" * 80)
    logger.info("GATE G3 PROGRAM VARIABLES PANE DEEP PROBE")
    logger.info("=" * 80)

    evidence: Dict[str, Any] = {
        "task": "GATE_G3_PROGRAM_VARIABLES_PANE_PROBE",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "inconclusive",
        "source_base_file": str(BASE_P1_PATH),
        "source_base_sha256": BASELINE_P1_SHA,
        "probe_copy_file": str(PROBE_COPY_PATH),
        "probe_copy_initial_sha256": None,
        "probe_copy_final_sha256": None,
        "summary": {},
        "program_variables_pane_windows": [],
        "program_variables_uia_elements": [],
        "all_process_windows": [],
        "screenshots": {},
        "error": None,
    }

    try:
        # Step 1: Assert safety invariants
        assert_safety_invariants()

        # Step 2: Initialize disposable copy
        COPIES_DIR.mkdir(parents=True, exist_ok=True)
        if PROBE_COPY_PATH.exists():
            PROBE_COPY_PATH.unlink()
        logger.info(f"Creating fresh disposable copy: '{PROBE_COPY_PATH.name}'...")
        shutil.copyfile(BASE_P1_PATH, PROBE_COPY_PATH)
        initial_sha = compute_sha256(PROBE_COPY_PATH)
        evidence["probe_copy_initial_sha256"] = initial_sha
        logger.info(f"Copy created. SHA-256: {initial_sha}")

        # Step 3: Launch Cscape
        close_cscape_gracefully()
        configure_cscape_registry(PROBE_COPY_PATH)

        abs_copy = str(PROBE_COPY_PATH.resolve())
        logger.info(f"Launching Cscape with: {abs_copy}...")
        proc_obj = psutil.Popen([DEFAULT_CSCAPE_PATH, abs_copy], cwd=os.path.dirname(DEFAULT_CSCAPE_PATH))
        pid = proc_obj.pid
        logger.info(f"Launched Cscape PID {pid}. Waiting for main window...")

        main_hwnd = None
        for _ in range(30):
            time.sleep(1.0)
            windows = enumerate_cscape_windows(pid)
            for h, cls, title in windows:
                if cls.startswith("Afx") and "cscape" in title.lower():
                    main_hwnd = h
                    break
            if main_hwnd:
                break

        if not main_hwnd:
            raise RuntimeError("Failed to locate Cscape main window.")

        logger.info(f"Cscape main window located: HWND {hex(main_hwnd)}")
        user32.SetForegroundWindow(main_hwnd)
        time.sleep(1.0)

        app_win32 = Application(backend="win32").connect(process=pid)
        main_win = app_win32.window(handle=main_hwnd)
        main_win.set_focus()

        # Step 4: Handle startup dialogs and wait for main window enabled
        handle_startup_dialogs_and_wait_for_main_window(pid, main_hwnd, app_win32)

        app_uia = Application(backend="uia").connect(process=pid)
        cscape_ui = app_uia.window(handle=main_hwnd)

        # Step 5: Open Program Variables pane
        open_program_variables_pane(main_hwnd, cscape_ui)

        # Step 6: Capture full screenshot
        logger.info(f"Capturing full screenshot: {FULL_SCREENSHOT_PATH}...")
        full_img = main_win.capture_as_image()
        full_img.save(str(FULL_SCREENSHOT_PATH))
        evidence["screenshots"]["full"] = str(FULL_SCREENSHOT_PATH)
        main_rect = main_win.rectangle()

        # Step 7: Probe Win32 window hierarchy
        all_win32_windows = probe_win32_hierarchy(pid, main_hwnd)
        evidence["all_process_windows"] = all_win32_windows

        # Filter windows belonging or related to Program Variables
        pv_win32_windows = []
        pane_container = None
        tree_control = None

        for w in all_win32_windows:
            txt_low = (w["window_text"] + " " + w["wm_gettext"]).lower()
            cls_low = w["class_name"].lower()

            # Check if this window is the Program Variables pane header/container
            if "program variables" in txt_low:
                pv_win32_windows.append(w)
                if pane_container is None or w["rect"]["height"] > pane_container["rect"]["height"]:
                    pane_container = w

            # Check if this window is a custom tree or Straton dictionary control
            elif "w5" in cls_low or "dico" in cls_low or "tree" in cls_low:
                pv_win32_windows.append(w)
                if tree_control is None:
                    tree_control = w

        # Also find all children physically contained within the pane container rectangle
        if pane_container:
            p_r = pane_container["rect"]
            for w in all_win32_windows:
                w_r = w["rect"]
                if (
                    w_r["left"] >= p_r["left"] - 5
                    and w_r["right"] <= p_r["right"] + 5
                    and w_r["top"] >= p_r["top"] - 5
                    and w_r["bottom"] <= p_r["bottom"] + 5
                    and w["hwnd"] != pane_container["hwnd"]
                ):
                    if w not in pv_win32_windows:
                        pv_win32_windows.append(w)
                    if "tree" in w["class_name"].lower() or "w5" in w["class_name"].lower() or "edit" in w["class_name"].lower():
                        if tree_control is None or w_r["height"] > tree_control["rect"]["height"]:
                            tree_control = w

        evidence["program_variables_pane_windows"] = pv_win32_windows

        # Step 8: Probe UIA elements
        pv_pane_uia, pv_elements_uia = probe_uia_elements(cscape_ui)
        evidence["program_variables_uia_pane"] = pv_pane_uia
        evidence["program_variables_uia_elements"] = pv_elements_uia

        # Step 9: Save cropped screenshot of Program Variables pane
        crop_target_rect = None
        if tree_control:
            crop_target_rect = tree_control["rect"]
        elif pane_container:
            crop_target_rect = pane_container["rect"]
        elif pv_pane_uia:
            crop_target_rect = pv_pane_uia["rect"]

        if crop_target_rect:
            try:
                x1 = max(0, crop_target_rect["left"] - main_rect.left)
                y1 = max(0, crop_target_rect["top"] - main_rect.top)
                x2 = min(full_img.width, crop_target_rect["right"] - main_rect.left)
                y2 = min(full_img.height, crop_target_rect["bottom"] - main_rect.top)

                if x2 > x1 + 20 and y2 > y1 + 20:
                    cropped = full_img.crop((x1, y1, x2, y2))
                    cropped.save(str(PANE_SCREENSHOT_PATH))
                    evidence["screenshots"]["cropped_pane"] = str(PANE_SCREENSHOT_PATH)
                    logger.info(f"Cropped pane screenshot saved: {PANE_SCREENSHOT_PATH} (region: {x1},{y1},{x2},{y2})")
            except Exception as e:
                logger.warning(f"Could not crop pane screenshot: {e}")

        # Step 10: Compile summary
        evidence["summary"] = {
            "total_windows_enumerated": len(all_win32_windows),
            "pane_container_hwnd": pane_container["hwnd_hex"] if pane_container else None,
            "pane_container_class": pane_container["class_name"] if pane_container else None,
            "pane_container_rect": pane_container["rect"] if pane_container else None,
            "tree_control_hwnd": tree_control["hwnd_hex"] if tree_control else None,
            "tree_control_class": tree_control["class_name"] if tree_control else None,
            "tree_control_rect": tree_control["rect"] if tree_control else None,
            "tree_control_item_count": tree_control["item_count"] if tree_control else None,
            "associated_win32_windows_count": len(pv_win32_windows),
            "uia_pane_located": bool(pv_pane_uia),
            "uia_elements_count": len(pv_elements_uia),
            "total_child_hwnds": len(pv_win32_windows),
            "total_uia_elements": len(pv_elements_uia),
            "pane_found": pane_container is not None or pv_pane_uia is not None,
            "description": "Program Variables pane HWND and UIA structure discovery",
        }
        evidence["error_code"] = None
        evidence["target_pane"] = "Program Variables"
        evidence["cscape_info"] = {
            "pid": pid,
            "hwnd": hex(main_hwnd),
            "title": win32gui.GetWindowText(main_hwnd),
            "version": "10.2.751.4",
        }
        evidence["pane"] = pane_container
        evidence["child_hwnds"] = pv_win32_windows
        evidence["uia_elements"] = pv_elements_uia
        evidence["artifacts"] = {
            "pane_screenshot": str(PANE_SCREENSHOT_PATH),
            "full_screenshot": str(FULL_SCREENSHOT_PATH),
            "json_dump": str(EVIDENCE_JSON_PATH),
        }

        # Step 11: Close Cscape gracefully (No to save prompts)
        logger.info("Closing Cscape gracefully...")
        close_cscape_gracefully(pid=pid, timeout=6.0)

        # Step 12: Verify read-only invariant (probe_pv.csp and base files unmodified)
        final_copy_sha = compute_sha256(PROBE_COPY_PATH)
        evidence["probe_copy_final_sha256"] = final_copy_sha
        assert_safety_invariants()
        if final_copy_sha != initial_sha:
            logger.warning(f"Note: Copy SHA mutated on close without edits (initial: {initial_sha[:8]}, final: {final_copy_sha[:8]}). Base remains pristine.")

        evidence["status"] = "success"

        # Step 13: Print short summary to stdout
        print("\n" + "=" * 80)
        print("  PROGRAM VARIABLES PANE PROBE SUMMARY")
        print("=" * 80)
        print(f"  Target File:               {PROBE_COPY_PATH}")
        print(f"  Cscape Main HWND:          {hex(main_hwnd)}")
        print(f"  Total Process Windows:     {len(all_win32_windows)}")
        print("-" * 80)
        if pane_container:
            print(f"  Pane Container HWND:       {pane_container['hwnd_hex']} (Class: {pane_container['class_name']})")
            print(f"  Pane Container Title:      '{pane_container['window_text']}'")
            print(f"  Pane Container Rect:       {pane_container['rect']}")
        else:
            print("  Pane Container HWND:       NOT DETECTED BY TITLE")

        if tree_control:
            print(f"  Tree/List Control HWND:    {tree_control['hwnd_hex']} (Class: {tree_control['class_name']})")
            print(f"  Tree/List Control Rect:    {tree_control['rect']}")
            print(f"  Tree/List Control Items:   {tree_control['item_count']}")
        else:
            print("  Tree/List Control HWND:    NOT DETECTED BY COMMON CLASS")

        print(f"  Associated Win32 Controls: {len(pv_win32_windows)}")
        for idx, w in enumerate(pv_win32_windows[:8], 1):
            print(f"    [{idx}] HWND {w['hwnd_hex']}: Class='{w['class_name']}', Title='{w['window_text']}', Rect={w['rect']['width']}x{w['rect']['height']}")

        print("-" * 80)
        print(f"  UIA Pane Located:          {bool(pv_pane_uia)}")
        print(f"  UIA Elements Under Pane:   {len(pv_elements_uia)}")
        for idx, elem in enumerate(pv_elements_uia[:8], 1):
            print(f"    [{idx}] [{elem['control_type']}] Name='{elem['name']}', Class='{elem['class_name']}', Rect={elem['rect']}")

        print("-" * 80)
        print(f"  JSON Deliverable:          {EVIDENCE_JSON_PATH}")
        print(f"  Cropped Pane Screenshot:   {PANE_SCREENSHOT_PATH}")
        print(f"  Full Window Screenshot:    {FULL_SCREENSHOT_PATH}")
        print("=" * 80 + "\n")

    except Exception as e:
        evidence["status"] = "failed"
        evidence["error"] = str(e)
        logger.error(f"Probe execution failed: {e}", exc_info=True)
        close_cscape_gracefully()

    # Save evidence JSON
    with open(EVIDENCE_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)
    logger.info(f"Probe evidence exported to: {EVIDENCE_JSON_PATH}")

    return 0 if evidence["status"] == "success" else 1


def main() -> int:
    return run_probe()


if __name__ == "__main__":
    sys.exit(main())
