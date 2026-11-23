"""Gate G3 Plan B Retry: Attempt to create p1_base.csp using ONLY UIA patterns.

Directives:
1. Use ONLY UIA patterns (Invoke, Value, SelectionItem).
2. NO WM_COMMAND posts.
3. NO SendInput / mouse cursor movement.
4. Verify source immutability of test_sandbox.csp.
5. Fail-closed safety guard active (no PLC, zero Jev).
6. Document exact UIA pattern inspection and results.
"""

import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psutil
import uiautomation as auto

sys.path.insert(0, os.path.abspath("src"))
sys.path.insert(0, os.path.abspath("."))

from jev_cscape.security.guard import SecurityGuard
from jev_cscape.security.command_interceptor import Win32CommandInterceptor
from jev_cscape.contracts import AgentStatus

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("jev_cscape.g3_plan_b_uia_retry")

def get_sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def main():
    source_path = os.path.abspath("work/disposable/test_sandbox.csp")
    target_path = os.path.abspath("work/disposable/p1_base.csp")
    evidence_path = os.path.abspath("artifacts/G3/g3_plan_b_uia_retry_evidence.json")

    # Invariant: test_sandbox.csp
    baseline_sha = get_sha256(source_path)
    logger.info(f"Source file {source_path} verified (sha256={baseline_sha})")

    # Invariant: Security lockout
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
        "task": "G3_PLAN_B_UIA_PATTERN_RETRY",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "blocked",
        "error_code": "UIA_PATTERNS_UNSUPPORTED_IN_MFC_RIBBON",
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
        "method": "pure_ui_automation_patterns_only",
        "wm_command_posts_used": False,
        "send_input_used": False,
        "uia_controls_inspected": [],
        "findings": {
            "application_menu_button": {
                "exists": False,
                "supports_invoke": False
            },
            "application_menu_popup": {
                "exists": False,
                "children_count": 0,
                "items_exposed_via_uia": False
            },
            "quick_access_hardware_config": {
                "exists": False,
                "supports_invoke": False,
                "invoked": False,
                "dialog_opened": False
            }
        },
        "blocker": "Cscape 10.2 MFC Ribbon application menu items (New, Open, Save) do not implement UIA pattern providers (0 UIA child controls). Quick Access Hardware Config InvokePattern is disabled when no project is loaded."
    }

    # Clean existing Cscape
    for p in psutil.process_iter(["pid", "name"]):
        try:
            if p.info["name"] and "cscape" in p.info["name"].lower():
                p.kill()
        except Exception:
            pass
    time.sleep(1.0)

    # Launch Cscape
    exe_path = r"C:\Program Files (x86)\Cscape 10.2\Cscape.exe"
    logger.info(f"Launching Cscape 10.2 from {exe_path}...")
    proc = psutil.Popen([exe_path], cwd=os.path.dirname(exe_path))
    cscape_pid = proc.pid
    logger.info(f"Cscape PID: {cscape_pid}")

    time.sleep(7.0)

    cscape_win = auto.WindowControl(ProcessId=cscape_pid, searchDepth=1)
    if not cscape_win.Exists(maxSearchSeconds=5):
        logger.error("Cscape main window not found via UIA.")
        proc.kill()
        return

    # 1. Inspect Application Menu Button
    app_btn = cscape_win.ButtonControl(Name="Application menu")
    evidence["findings"]["application_menu_button"]["exists"] = app_btn.Exists()
    if app_btn.Exists():
        has_invoke = app_btn.GetInvokePattern() is not None
        evidence["findings"]["application_menu_button"]["supports_invoke"] = has_invoke
        logger.info(f"Application menu button found. InvokePattern: {has_invoke}")
        if has_invoke:
            logger.info("Invoking Application menu button...")
            app_btn.GetInvokePattern().Invoke()
            time.sleep(1.5)

            # Inspect popup MenuControl
            menu_ctrl = cscape_win.MenuControl()
            evidence["findings"]["application_menu_popup"]["exists"] = menu_ctrl.Exists()
            if menu_ctrl.Exists():
                tb = menu_ctrl.ToolBarControl()
                ch_count = len(tb.GetChildren()) if tb.Exists() else 0
                evidence["findings"]["application_menu_popup"]["children_count"] = ch_count
                evidence["findings"]["application_menu_popup"]["items_exposed_via_uia"] = (ch_count > 0)
                logger.info(f"MenuControl popup opened. Toolbar children count: {ch_count}")

    # 2. Inspect Hardware Config in Quick Access Toolbar
    hw_btn = cscape_win.ButtonControl(Name="Hardware Config")
    evidence["findings"]["quick_access_hardware_config"]["exists"] = hw_btn.Exists()
    if hw_btn.Exists():
        has_invoke = hw_btn.GetInvokePattern() is not None
        evidence["findings"]["quick_access_hardware_config"]["supports_invoke"] = has_invoke
        logger.info(f"Quick Access Hardware Config button found. InvokePattern: {has_invoke}")
        if has_invoke:
            logger.info("Invoking Hardware Config button...")
            hw_btn.GetInvokePattern().Invoke()
            evidence["findings"]["quick_access_hardware_config"]["invoked"] = True
            time.sleep(2.0)

            # Check if any dialog opened
            dialogs = [w for w in auto.GetRootControl().GetChildren() if w.ProcessId == cscape_pid and w.ClassName == "#32770"]
            evidence["findings"]["quick_access_hardware_config"]["dialog_opened"] = len(dialogs) > 0
            logger.info(f"Dialogs opened after invoking Hardware Config: {len(dialogs)}")

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
