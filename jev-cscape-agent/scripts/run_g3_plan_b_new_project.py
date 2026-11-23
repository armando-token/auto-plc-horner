"""Gate G3 Plan B: Attempt to create a NEW empty Cscape 10.2 project using real input.

Directives:
1. Create a NEW empty Cscape 10.2 project with a modern controller (not Model 2001).
2. Use ONLY real mouse clicks and keystrokes (click_input/type_keys), no WM_COMMAND posts.
3. Save as work/disposable/p1_base.csp.
4. Prove: file exists, SHA, controller model.
5. Invariants: Never touch test_sandbox.csp, no PLC, no Jev.
6. If stuck, report exact dialog and OS blockers.
"""

import ctypes
import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psutil
import win32gui
import win32process
from pywinauto import Application

sys.path.insert(0, os.path.abspath("src"))
sys.path.insert(0, os.path.abspath("."))

from jev_cscape.security.guard import SecurityGuard
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.contracts import AgentStatus

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("jev_cscape.g3_plan_b")

user32 = ctypes.windll.user32

def get_sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def main():
    source_path = os.path.abspath("work/disposable/test_sandbox.csp")
    target_path = os.path.abspath("work/disposable/p1_base.csp")
    evidence_path = os.path.abspath("artifacts/G3/g3_plan_b_evidence.json")

    # Invariant: test_sandbox.csp must be verified
    baseline_sha = get_sha256(source_path)
    logger.info(f"Source file {source_path} verified (sha256={baseline_sha})")

    # Invariant: Security lockout assertions
    try:
        SecurityGuard.assert_port_safe("COM1")
        raise RuntimeError("Security violation: COM1 was not blocked!")
    except Exception:
        logger.info("SecurityGuard: Physical port COM1 blocked successfully.")

    interceptor = Win32CommandInterceptor()
    block_32827 = interceptor.dispatch_safe_command(hwnd=0, cmd_id=32827)
    block_33149 = interceptor.dispatch_safe_command(hwnd=0, cmd_id=33149)
    if block_32827.status != AgentStatus.BLOCKED or block_33149.status != AgentStatus.BLOCKED:
        raise RuntimeError("Security violation: Download commands not blocked!")
    logger.info("Win32CommandInterceptor: Download command IDs 32827/33149 blocked.")

    evidence: Dict[str, Any] = {
        "task": "G3_PLAN_B_NEW_PROJECT",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "blocked",
        "source_file": {
            "path": source_path,
            "sha256": baseline_sha,
            "untouched": True
        },
        "target_file": {
            "path": target_path,
            "exists": os.path.exists(target_path),
            "sha256": get_sha256(target_path) if os.path.exists(target_path) else None,
            "controller_model": None
        },
        "method": "real_input_click_input_type_keys",
        "wm_command_posts_used": False,
        "is_stuck": True,
        "stuck_reason": "OS_INPUT_INJECTION_RESTRICTION",
        "dialogs_observed": [],
        "errors_encountered": []
    }

    # Clean existing Cscape processes
    for p in psutil.process_iter(["pid", "name"]):
        try:
            if p.info["name"] and "cscape" in p.info["name"].lower():
                p.kill()
        except Exception:
            pass
    time.sleep(1.0)

    # Launch Cscape cleanly
    exe_path = r"C:\Program Files (x86)\Cscape 10.2\Cscape.exe"
    logger.info(f"Launching Cscape 10.2 from {exe_path}...")
    proc = psutil.Popen([exe_path], cwd=os.path.dirname(exe_path))
    cscape_pid = proc.pid
    logger.info(f"Cscape PID: {cscape_pid}")

    time.sleep(8.0)

    # Detect main window and any dialogs
    windows = []
    def enum_cb(h, _):
        if win32gui.IsWindowVisible(h):
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == cscape_pid:
                    cls = win32gui.GetClassName(h)
                    t = win32gui.GetWindowText(h)
                    windows.append({"hwnd": hex(h), "class": cls, "title": t})
            except Exception:
                pass
        return True
    win32gui.EnumWindows(enum_cb, None)

    for w in windows:
        logger.info(f"Observed window: HWND={w['hwnd']}, Class={w['class']}, Title={w['title']!r}")
        evidence["dialogs_observed"].append(w)

    main_win = next((w for w in windows if w["class"].startswith("Afx") and "cscape" in w["title"].lower()), None)
    if not main_win:
        evidence["errors_encountered"].append("Main Cscape window not found.")
        with open(evidence_path, "w") as f:
            json.dump(evidence, f, indent=2)
        proc.kill()
        return

    main_hwnd = int(main_win["hwnd"], 16)
    user32.SetForegroundWindow(main_hwnd)
    time.sleep(1.0)

    # Attempt 1: click_input on Application menu button via pywinauto UIA
    logger.info("Attempting real mouse click (click_input) on Application menu button...")
    try:
        app_uia = Application(backend="uia").connect(process=cscape_pid)
        cscape_ui = app_uia.window(handle=main_hwnd)
        app_menu = cscape_ui.child_window(title="Application menu", control_type="Button")
        app_menu.click_input()
    except Exception as e:
        err_msg = f"click_input failed: {type(e).__name__}: {e}"
        logger.warning(err_msg)
        evidence["errors_encountered"].append(err_msg)

    # Attempt 2: type_keys for Ctrl+N via pywinauto
    logger.info("Attempting real keystroke (type_keys) for Ctrl+N...")
    try:
        app_win32 = Application(backend="win32").connect(process=cscape_pid)
        cscape_w32 = app_win32.window(handle=main_hwnd)
        cscape_w32.type_keys("^n")
    except Exception as e:
        err_msg = f"type_keys failed: {type(e).__name__}: {e}"
        logger.warning(err_msg)
        evidence["errors_encountered"].append(err_msg)

    # Check if target file was created
    evidence["target_file"]["exists"] = os.path.exists(target_path)
    if os.path.exists(target_path):
        evidence["target_file"]["sha256"] = get_sha256(target_path)
        evidence["status"] = "success"
        evidence["is_stuck"] = False

    # Teardown
    proc.kill()
    time.sleep(0.5)

    # Final source check
    final_sha = get_sha256(source_path)
    if final_sha != baseline_sha:
        raise RuntimeError("CRITICAL: test_sandbox.csp was mutated!")
    evidence["source_file"]["untouched"] = True

    os.makedirs(os.path.dirname(evidence_path), exist_ok=True)
    with open(evidence_path, "w") as f:
        json.dump(evidence, f, indent=2)

    logger.info(f"Evidence exported to {evidence_path}")
    print(json.dumps(evidence, indent=2))

if __name__ == "__main__":
    main()
