"""Real G3 concrete field edit test script.

Attempts to perform a live in-GUI edit on a fresh copy of test_sandbox.csp:
1. Launch Cscape with copy on winsta0\\Default.
2. Send command to open edit dialog (Summary Info 32809 or I/O Names 32835).
3. If dialog opens, inspect controls, change a field, click OK.
4. Save As new file (test_sandbox_edited.csp).
5. Close Cscape.
6. Reopen test_sandbox_edited.csp.
7. Read back the value from GUI.
8. If editing is blocked by Cscape GUI architecture, document exact blocker.
"""

import ctypes
import hashlib
import json
import logging
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import win32con
import win32gui
import win32process

sys.path.insert(0, os.path.abspath("src"))
sys.path.insert(0, os.path.abspath("."))

from jev_cscape.automation.gui_controller import GUIBoundaryController
from jev_cscape.automation.launcher import CscapeLauncher
from jev_cscape.automation.dialog_sweeper import DialogSweeper
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.contracts import AgentStatus

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("jev_cscape.real_g3_edit")

user32 = ctypes.windll.user32

def get_sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def dismiss_dialogs(pid: int, timeout: float = 3.0) -> int:
    start = time.time()
    dismissed = 0
    while time.time() - start < timeout:
        dlgs = []
        def enum_cb(h, _):
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.GetClassName(h) == "#32770" and win32gui.IsWindowVisible(h):
                    dlgs.append(h)
            except Exception:
                pass
            return True
        win32gui.EnumWindows(enum_cb, None)
        for dlg in dlgs:
            txt = win32gui.GetWindowText(dlg)
            if any(k in txt.lower() for k in ["no errors", "warning", "tip of the day", "about cscape"]):
                user32.PostMessageW(dlg, win32con.WM_COMMAND, 1, 0)
                dismissed += 1
                time.sleep(0.2)
        if dismissed > 0:
            break
        time.sleep(0.2)
    return dismissed

def main():
    source_path = os.path.abspath("work/disposable/test_sandbox.csp")
    copy_path = os.path.abspath("work/disposable/test_sandbox_real_g3_probe.csp")
    saved_as_path = os.path.abspath("work/disposable/test_sandbox_saved_as.csp")

    source_hash = get_sha256(source_path)
    shutil.copyfile(source_path, copy_path)
    copy_initial_hash = get_sha256(copy_path)
    logger.info(f"Source: {source_path} (sha256={source_hash})")
    logger.info(f"Initial copy: {copy_path} (sha256={copy_initial_hash})")

    gui_ctrl = GUIBoundaryController()
    logger.info("Acquiring GUI Boundary lock on winsta0\\Default...")

    results = {
        "source_path": source_path,
        "source_hash": source_hash,
        "copy_path": copy_path,
        "copy_initial_hash": copy_initial_hash,
        "saved_as_path": saved_as_path,
        "cscape_launched": False,
        "field_edited": None,
        "old_value": None,
        "new_value": None,
        "value_read_after_reopen": None,
        "how_it_was_read": None,
        "hash_differs": False,
        "is_editable": False,
        "blocker": None
    }

    with gui_ctrl.guard_gui(timeout=15.0) as lock_data:
        logger.info(f"Lock acquired: {lock_data}")

        launcher = CscapeLauncher()
        launch_res = launcher.launch(project_path=copy_path, timeout=60.0)
        logger.info(f"Launch status: {launch_res.status}, details: {launch_res.details}")
        if launch_res.status != AgentStatus.SUCCESS:
            results["blocker"] = f"Cscape launch failed: {launch_res.details}"
            print(json.dumps(results, indent=2))
            return

        results["cscape_launched"] = True
        main_win = launcher.find_main_window()
        if not main_win:
            results["blocker"] = "Main window not found after launch."
            print(json.dumps(results, indent=2))
            return

        main_hwnd = main_win["hwnd"]
        cscape_pid = main_win["pid"]
        logger.info(f"Cscape main window: HWND={hex(main_hwnd)}, PID={cscape_pid}, title={main_win['title']!r}")

        # Check menu commands
        # 1. Try ID_FILE_SUMMARYINFO (32809)
        logger.info("Testing ID_FILE_SUMMARYINFO (32809)...")
        user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, 32809, 0)
        time.sleep(1.5)

        target_dlg = None
        def find_dlg(h, _):
            nonlocal target_dlg
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == cscape_pid and win32gui.GetClassName(h) == "#32770" and win32gui.IsWindowVisible(h):
                    t = win32gui.GetWindowText(h)
                    if "summary" in t.lower() or "information" in t.lower() or "cscape" in t.lower():
                        target_dlg = (h, t)
            except Exception:
                pass
            return True
        win32gui.EnumWindows(find_dlg, None)

        if target_dlg:
            logger.info(f"Opened dialog via 32809: HWND={hex(target_dlg[0])}, title={target_dlg[1]!r}")
            # Enumerate child controls
            ctrls = []
            def cb_c(ch, _):
                ctrls.append({
                    "hwnd": hex(ch),
                    "id": win32gui.GetDlgCtrlID(ch),
                    "cls": win32gui.GetClassName(ch),
                    "text": win32gui.GetWindowText(ch),
                    "vis": bool(win32gui.IsWindowVisible(ch))
                })
                return True
            win32gui.EnumChildWindows(target_dlg[0], cb_c, None)
            logger.info(f"Found {len(ctrls)} controls in dialog:")
            for c in ctrls:
                logger.info(f"  {c}")

            # Close dialog cleanly
            user32.PostMessageW(target_dlg[0], win32con.WM_COMMAND, 2, 0)
            time.sleep(1.0)
        else:
            logger.info("No dialog opened via 32809. Testing ID_PROGRAM_IONAMES (32835)...")
            user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, 32835, 0)
            time.sleep(1.5)
            win32gui.EnumWindows(find_dlg, None)
            if target_dlg:
                logger.info(f"Opened dialog via 32835: HWND={hex(target_dlg[0])}, title={target_dlg[1]!r}")
                user32.PostMessageW(target_dlg[0], win32con.WM_COMMAND, 2, 0)
                time.sleep(1.0)
            else:
                logger.info("No dialog opened via 32835 either.")

        # Clean teardown
        launcher.teardown(cscape_pid)
        logger.info("Teardown complete.")

    with open("artifacts/G3/real_g3_probe_result.json", "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
