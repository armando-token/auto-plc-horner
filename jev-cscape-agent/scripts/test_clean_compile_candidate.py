"""Test candidate example projects to find one that compiles cleanly (0 errors, 0 warnings).

Runs strictly under Single GUI Boundary Controller lock on winsta0\\Default.
"""

import os
import sys
import shutil
import time
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("candidate_test")

sys.path.insert(0, os.path.abspath("src"))
sys.path.insert(0, os.path.abspath("."))

from jev_cscape.automation.lifecycle import CscapeLifecycleController
from jev_cscape.automation.gui_controller import GUIBoundaryController
from jev_cscape.automation.compiler import CscapeCompilerDispatcher
from jev_cscape.contracts import AgentStatus

EXAMPLES_DIR = r"C:\Program Files (x86)\Cscape 10.2\Examples"
CANDIDATES = [
    "random.csp",
    "series coils.csp",
    "reg_min.csp",
    "barcode length.csp",
    "data_log.csp",
    "graph_example.csp",
]

def test_candidate(candidate_name: str) -> dict:
    src_file = os.path.join(EXAMPLES_DIR, candidate_name)
    if not os.path.exists(src_file):
        return {"file": candidate_name, "status": "not_found"}

    clean_name = candidate_name.replace(" ", "_")
    dest_file = os.path.abspath(os.path.join("work", "disposable", f"test_{clean_name}"))
    os.makedirs(os.path.dirname(dest_file), exist_ok=True)
    shutil.copy2(src_file, dest_file)

    gui_ctrl = GUIBoundaryController()
    lifecycle = CscapeLifecycleController()
    compiler = CscapeCompilerDispatcher()

    logger.info(f"Testing candidate: {candidate_name}")
    lock_res = gui_ctrl.acquire_lock(timeout=10.0)
    if lock_res.status != AgentStatus.SUCCESS:
        return {"file": candidate_name, "status": "lock_failed"}

    try:
        launch_res = lifecycle.launch(project_path=dest_file, timeout=25.0)
        if launch_res.status != AgentStatus.SUCCESS:
            return {"file": candidate_name, "status": "launch_failed", "details": launch_res.details}

        main_win = lifecycle.find_main_window()
        if not main_win:
            lifecycle.close(timeout=5.0)
            return {"file": candidate_name, "status": "no_main_window"}

        main_hwnd = main_win["hwnd"]
        pid = main_win["pid"]

        time.sleep(2.0)
        lifecycle.dismiss_startup_dialogs(pid=pid)

        # Release lock so compiler dispatcher can acquire it
        gui_ctrl.release_lock()

        scrape_res = compiler.trigger_and_scrape(main_hwnd=main_hwnd, settling_delay=3.0)
        
        # Re-acquire to close cleanly
        gui_ctrl.acquire_lock(timeout=5.0)
        lifecycle.close(timeout=8.0)

        err_count = scrape_res.data.get("error_count", 0) if scrape_res.data else -1
        warn_count = scrape_res.data.get("warning_count", 0) if scrape_res.data else -1

        return {
            "file": candidate_name,
            "status": scrape_res.status.value,
            "error_count": err_count,
            "warning_count": warn_count,
            "details": scrape_res.details,
            "clean": (err_count == 0 and warn_count == 0)
        }
    finally:
        gui_ctrl.release_lock()

if __name__ == "__main__":
    for cand in CANDIDATES:
        res = test_candidate(cand)
        print(f"RESULT: {res}")
        if res.get("clean"):
            print(f"FOUND CLEAN PROJECT: {cand}")
            break
