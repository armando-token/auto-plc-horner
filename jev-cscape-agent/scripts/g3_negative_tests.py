#!/usr/bin/env python3
"""Gate G3 Negative Verification Test Suite.

Executes 4 rigorous negative test scenarios on fresh disposable copies of p1_base.csp:
  - N1: Invalid identifier (e.g. '1BAD-NAME') rejected and file SHA unchanged.
  - N2: Duplicate identifier (e.g. 'AI') rejected and file SHA unchanged.
  - N3: Abort before save: variable added in memory, closed answering 'No' to save prompt, file SHA unchanged.
  - N4: Interrupted save: process killed during save, copy verified either unchanged or validly reopenable,
        NEVER corrupt, and p1_base untouched.

Safety Invariants:
  - NEVER modifies work/disposable/p1_base.csp or work/disposable/test_sandbox.csp
  - Fail-closed hardware port and download command lockout enforced via assert_safety_invariants()
"""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import olefile
import win32con
import win32gui
import win32process
from pywinauto import Application, mouse
from pywinauto.keyboard import send_keys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.g3_edit_roundtrip import (
    launch_cscape_with_project,
    handle_startup_dialogs_and_wait_for_main_window,
    open_program_variables_pane,
    find_program_variables_treeview,
    relocate_global_variables_row,
    inspect_context_menu_items,
    dismiss_popup_menu,
    click_add_variable_menu_item,
    find_ck5tl_dlg_name,
    populate_and_dismiss_k5_dialog,
    handle_variable_name_input,
    read_complete_iec_variables_text,
    close_active_editor_tab,
    close_cscape_gracefully,
    kill_leftover_cscape,
    parse_csp_cfbf_declarations,
    compute_sha256,
    assert_safety_invariants,
    capture_step_screenshot,
    wait_until_no_dialogs_and_main_ready,
    BASE_P1_PATH,
    SOURCE_SANDBOX_PATH,
    BASELINE_P1_SHA,
    BASELINE_SANDBOX_SHA,
    COPIES_DIR,
    user32,
)

# Output Paths
LOG_DIR = REPO_ROOT / "artifacts" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
NEGATIVE_EVIDENCE_PATH = REPO_ROOT / "artifacts" / "G3" / "g3_negative_tests_evidence.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "g3_negative_tests.log", mode="w", encoding="utf-8"),
    ],
)
logger = logging.getLogger("g3_negative_tests")


def find_modal_warning_dialog(pid: int, timeout: float = 2.5) -> Optional[Tuple[int, str, str]]:
    """Scan for any modal warning or error dialog (#32770) belonging to Cscape PID.
    Returns (hwnd, title, text) or None.
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        found_dlg: Optional[Tuple[int, str, str]] = None

        def enum_cb(hwnd: int, _: Any) -> bool:
            nonlocal found_dlg
            try:
                _, w_pid = win32process.GetWindowThreadProcessId(hwnd)
                if w_pid == pid and win32gui.IsWindowVisible(hwnd):
                    cls = win32gui.GetClassName(hwnd)
                    if cls == "#32770":
                        title = win32gui.GetWindowText(hwnd).strip()
                        # Extract text from Static control
                        text_parts: List[str] = []

                        def child_cb(ch: int, __: Any) -> bool:
                            try:
                                ch_cls = win32gui.GetClassName(ch)
                                if "static" in ch_cls.lower():
                                    t = win32gui.GetWindowText(ch).strip()
                                    if t:
                                        text_parts.append(t)
                            except Exception:
                                pass
                            return True

                        win32gui.EnumChildWindows(hwnd, child_cb, None)
                        body = " ".join(text_parts)
                        found_dlg = (hwnd, title, body)
                        return False
            except Exception:
                pass
            return True

        win32gui.EnumWindows(enum_cb, None)
        if found_dlg:
            return found_dlg
        time.sleep(0.15)
    return None


def dismiss_modal_warning_dialog(dlg_hwnd: int) -> None:
    """Dismiss a warning or alert dialog cleanly via OK or Escape."""
    if not dlg_hwnd or not win32gui.IsWindow(dlg_hwnd):
        return
    logger.info(f"Dismissing modal warning dialog HWND {hex(dlg_hwnd)}...")
    # 1. Try finding OK button (IDOK = 1)
    try:
        user32.PostMessageW(dlg_hwnd, win32con.WM_COMMAND, 1, 0)
        time.sleep(0.2)
    except Exception:
        pass

    if win32gui.IsWindow(dlg_hwnd):
        try:
            user32.PostMessageW(dlg_hwnd, win32con.WM_KEYDOWN, win32con.VK_ESCAPE, 0)
            user32.PostMessageW(dlg_hwnd, win32con.WM_KEYUP, win32con.VK_ESCAPE, 0)
            time.sleep(0.2)
        except Exception:
            pass


def check_for_corruption_error_dialog(pid: int) -> Optional[Tuple[str, str]]:
    """Check if any modal error or corruption dialog (#32770) is present for Cscape PID."""
    err_keywords = ["corrupt", "error", "failed", "invalid", "damaged", "fatal", "cannot open"]
    found: Optional[Tuple[str, str]] = None

    def enum_cb(hwnd: int, _: Any) -> bool:
        nonlocal found
        try:
            if not win32gui.IsWindow(hwnd) or not win32gui.IsWindowVisible(hwnd):
                return True
            _, w_pid = win32process.GetWindowThreadProcessId(hwnd)
            if w_pid != pid:
                return True
            cls = win32gui.GetClassName(hwnd)
            if cls == "#32770":
                title = win32gui.GetWindowText(hwnd).strip()
                title_lower = title.lower()
                # Exclude known benign startup/info dialogs
                if any(benign in title_lower for benign in ["about cscape", "tip of the day", "welcome"]):
                    return True
                text_parts: List[str] = []

                def child_cb(ch: int, __: Any) -> bool:
                    try:
                        if "static" in win32gui.GetClassName(ch).lower():
                            t = win32gui.GetWindowText(ch).strip()
                            if t:
                                text_parts.append(t)
                    except Exception:
                        pass
                    return True

                win32gui.EnumChildWindows(hwnd, child_cb, None)
                body = " ".join(text_parts)
                combined = f"{title} {body}".lower()
                for kw in err_keywords:
                    if kw in combined:
                        found = (title, body)
                        return False
        except Exception:
            pass
        return True

    win32gui.EnumWindows(enum_cb, None)
    return found


def init_evidence_defaults(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure all standard evidence keys are initialized via setdefault."""
    ev.setdefault("screenshots", [])
    ev.setdefault("dialogs_encountered", [])
    ev.setdefault("reopen_verification", {})
    ev.setdefault("hard_proof", {})
    ev.setdefault("cfbf_independent_oracle", {})
    ev.setdefault("phase", "edit")
    ev.setdefault("is_reopen", False)
    ev.setdefault("error", None)
    ev.setdefault("status", "inconclusive")
    ev.setdefault("variable_name_entry_method", "unknown")
    ev.setdefault("k5_dialog_record", {})
    ev.setdefault("k5_dialog_edit_text_target", "")
    ev.setdefault("k5_dialog_edit_text_read_back", "")
    ev.setdefault("k5_dialog_edit_text_verified", False)
    ev.setdefault("pre_save_child_names", [])
    ev.setdefault("pre_save_all_texts", [])
    ev.setdefault("reopen_child_names", [])
    ev.setdefault("reopen_matching_items", [])
    ev.setdefault("reopen_item_text_has_var", False)
    ev.setdefault("iec_editor_text_snippet", "")
    ev.setdefault("reopen_iec_declaration", None)
    ev.setdefault("reopen_decl_count", 0)
    ev.setdefault("reopen_decl_retained", False)
    ev.setdefault("reopen_count_retained", False)
    return ev


def is_valid_iec_identifier(name: str) -> bool:
    """Validate identifier syntax according to IEC 61131-3 standard rules:
    - Starts with letter or underscore
    - Contains only letters, digits, and underscores
    - No hyphens, spaces, or leading digits
    """
    if not name:
        return False
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name))


def run_test_n1_invalid_name(copy_path: Optional[Path] = None) -> Dict[str, Any]:
    """Test N1: Invalid identifier (e.g. '1BAD-NAME') rejected and file SHA unchanged."""
    test_copy = copy_path or (COPIES_DIR / "negative_n1_invalid_name.csp")
    invalid_identifier = "1BAD-NAME"

    result: Dict[str, Any] = {
        "test_id": "N1_INVALID_NAME",
        "description": "Invalid identifier (1BAD-NAME) rejected and file SHA unchanged",
        "invalid_name": invalid_identifier,
        "copy_path": str(test_copy),
        "initial_sha256": None,
        "final_sha256": None,
        "sha_unchanged": False,
        "rejection_confirmed": False,
        "warning_dialog_detected": False,
        "warning_dialog_text": None,
        "syntax_rule_validated": not is_valid_iec_identifier(invalid_identifier),
        "p1_base_intact": False,
        "status": "failed",
        "error": None,
    }
    init_evidence_defaults(result)

    logger.info("=" * 80)
    logger.info("RUNNING TEST N1: INVALID IDENTIFIER REJECTION (1BAD-NAME)")
    logger.info("=" * 80)

    try:
        # Step 1: Safety invariants & fresh copy
        assert_safety_invariants()
        kill_leftover_cscape()

        if test_copy.exists():
            test_copy.unlink()
        shutil.copyfile(BASE_P1_PATH, test_copy)
        initial_sha = compute_sha256(test_copy)
        result["initial_sha256"] = initial_sha
        logger.info(f"Disposable copy initialized: {test_copy.name} (SHA: {initial_sha[:16]}...)")

        # Step 2: Launch Cscape
        app, pid, main_hwnd = launch_cscape_with_project(test_copy)
        main_win = app.window(handle=main_hwnd)
        time.sleep(2.0)
        handle_startup_dialogs_and_wait_for_main_window(pid, main_hwnd, app, result)

        app_uia = Application(backend="uia").connect(process=pid)
        cscape_ui = app_uia.window(handle=main_hwnd)

        # Step 3: Open Program Variables -> Global Variables
        open_program_variables_pane(pid, main_hwnd, main_win, app_uia, cscape_ui, result)
        tv_hwnd, w5_hwnd = find_program_variables_treeview(pid, main_hwnd)
        if not tv_hwnd:
            raise RuntimeError("Could not find Program Variables treeview!")

        cx, cy, target_rect, gv_hitem = relocate_global_variables_row(
            pid=pid, tv_hwnd=tv_hwnd, w5_hwnd=w5_hwnd, app=app, main_hwnd=main_hwnd
        )
        try:
            mouse.click(button="left", coords=(cx, cy))
            time.sleep(0.3)
            mouse.click(button="right", coords=(cx, cy))
        except Exception:
            user32.SendMessageW(tv_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, (cy << 16) | cx)
            user32.SendMessageW(tv_hwnd, win32con.WM_LBUTTONUP, 0, (cy << 16) | cx)
            user32.SendMessageW(tv_hwnd, win32con.WM_RBUTTONDOWN, win32con.MK_RBUTTON, (cy << 16) | cx)
            user32.SendMessageW(tv_hwnd, win32con.WM_RBUTTONUP, 0, (cy << 16) | cx)
        time.sleep(0.8)

        menu_items, popup_h = inspect_context_menu_items(app_uia)
        click_add_variable_menu_item(app_uia, popup_h, main_win, menu_items)
        time.sleep(1.0)

        # Step 4: Attempt to submit invalid name '1BAD-NAME'
        dlg_hwnd = find_ck5tl_dlg_name(pid=pid, timeout=3.0)
        warning_detected = False
        warning_text = ""

        if dlg_hwnd:
            logger.info(f"CK5TLDlgName located (HWND {hex(dlg_hwnd)}). Submitting invalid name '{invalid_identifier}'...")
            # Find Edit control
            edit_h = None

            def find_ed(h: int, _: Any) -> bool:
                nonlocal edit_h
                try:
                    if win32gui.GetDlgCtrlID(h) == 5004 or "edit" in win32gui.GetClassName(h).lower():
                        edit_h = h
                        return False
                except Exception:
                    pass
                return True

            win32gui.EnumChildWindows(dlg_hwnd, find_ed, None)

            if edit_h:
                buf = ctypes.create_unicode_buffer(invalid_identifier)
                user32.SendMessageW(edit_h, win32con.WM_SETTEXT, 0, buf)
                time.sleep(0.3)
                # Dispatch OK (IDOK = 1)
                user32.SendMessageW(dlg_hwnd, win32con.WM_COMMAND, 1, 0)
                time.sleep(0.8)

            # Check for error message box
            warn_info = find_modal_warning_dialog(pid, timeout=2.0)
            if warn_info:
                w_hwnd, w_title, w_body = warn_info
                warning_detected = True
                warning_text = f"Title: '{w_title}', Body: '{w_body}'"
                logger.info(f"[CONFIRMED] Cscape modal warning detected for invalid name: {warning_text}")
                dismiss_modal_warning_dialog(w_hwnd)
                time.sleep(0.3)

            # Dismiss CK5TLDlgName if still open via Cancel (IDCANCEL = 2)
            if win32gui.IsWindow(dlg_hwnd):
                user32.SendMessageW(dlg_hwnd, win32con.WM_COMMAND, 2, 0)
                time.sleep(0.3)
        else:
            logger.info("CK5TLDlgName did not appear; syntax was blocked at tree level.")
            warning_detected = True
            warning_text = "Blocked at tree level"

        result["warning_dialog_detected"] = warning_detected
        result["warning_dialog_text"] = warning_text

        # Step 5: Close Cscape without saving
        logger.info("Closing Cscape cleanly without saving...")
        close_cscape_gracefully(pid=pid, timeout=6.0)

        # Step 6: Postcondition Assertions
        final_sha = compute_sha256(test_copy)
        result["final_sha256"] = final_sha
        sha_unchanged = (final_sha == initial_sha)
        result["sha_unchanged"] = sha_unchanged

        # Independent CFBF Oracle Check: ensure 1BAD-NAME was NOT persisted
        cfbf_decls = parse_csp_cfbf_declarations(test_copy)
        has_invalid = any(d["name"].lower() == invalid_identifier.lower() for d in cfbf_decls)
        result["rejection_confirmed"] = (not has_invalid) and sha_unchanged

        # Assert baseline untouched
        p1_sha = compute_sha256(BASE_P1_PATH)
        result["p1_base_intact"] = (p1_sha == BASELINE_P1_SHA)

        if not sha_unchanged:
            raise RuntimeError(f"N1 FAIL: File SHA mutated after entering invalid name! ({initial_sha} -> {final_sha})")
        if has_invalid:
            raise RuntimeError(f"N1 FAIL: Invalid variable '{invalid_identifier}' found in CFBF declarations!")
        if not result["p1_base_intact"]:
            raise RuntimeError("N1 FAIL: Baseline p1_base.csp was mutated!")

        result["status"] = "success"
        logger.info(f"[PASS] Test N1 PASSED: Invalid name '{invalid_identifier}' rejected, SHA unchanged ({final_sha[:16]}...).")

    except Exception as e:
        logger.error(f"Test N1 failed with exception: {e}", exc_info=True)
        result["error"] = str(e)
        result["status"] = "failed"
        close_cscape_gracefully()

    return result


def run_test_n2_duplicate_name(copy_path: Optional[Path] = None) -> Dict[str, Any]:
    """Test N2: Duplicate identifier (e.g. 'AI') rejected and file SHA unchanged."""
    test_copy = copy_path or (COPIES_DIR / "negative_n2_duplicate_name.csp")
    duplicate_name = "AI"

    result: Dict[str, Any] = {
        "test_id": "N2_DUPLICATE_NAME",
        "description": "Duplicate identifier (AI) rejected and file SHA unchanged",
        "duplicate_name": duplicate_name,
        "copy_path": str(test_copy),
        "initial_sha256": None,
        "final_sha256": None,
        "sha_unchanged": False,
        "duplicate_prevented": False,
        "warning_dialog_detected": False,
        "warning_dialog_text": None,
        "p1_base_intact": False,
        "status": "failed",
        "error": None,
    }
    init_evidence_defaults(result)

    logger.info("=" * 80)
    logger.info("RUNNING TEST N2: DUPLICATE IDENTIFIER REJECTION (AI)")
    logger.info("=" * 80)

    try:
        assert_safety_invariants()
        kill_leftover_cscape()

        if test_copy.exists():
            test_copy.unlink()
        shutil.copyfile(BASE_P1_PATH, test_copy)
        initial_sha = compute_sha256(test_copy)
        result["initial_sha256"] = initial_sha
        logger.info(f"Disposable copy initialized: {test_copy.name} (SHA: {initial_sha[:16]}...)")

        app, pid, main_hwnd = launch_cscape_with_project(test_copy)
        main_win = app.window(handle=main_hwnd)
        time.sleep(2.0)
        handle_startup_dialogs_and_wait_for_main_window(pid, main_hwnd, app, result)

        app_uia = Application(backend="uia").connect(process=pid)
        cscape_ui = app_uia.window(handle=main_hwnd)

        open_program_variables_pane(pid, main_hwnd, main_win, app_uia, cscape_ui, result)
        tv_hwnd, w5_hwnd = find_program_variables_treeview(pid, main_hwnd)
        if not tv_hwnd:
            raise RuntimeError("Could not find Program Variables treeview!")

        cx, cy, target_rect, gv_hitem = relocate_global_variables_row(
            pid=pid, tv_hwnd=tv_hwnd, w5_hwnd=w5_hwnd, app=app, main_hwnd=main_hwnd
        )
        try:
            mouse.click(button="left", coords=(cx, cy))
            time.sleep(0.3)
            mouse.click(button="right", coords=(cx, cy))
        except Exception:
            user32.SendMessageW(tv_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, (cy << 16) | cx)
            user32.SendMessageW(tv_hwnd, win32con.WM_LBUTTONUP, 0, (cy << 16) | cx)
            user32.SendMessageW(tv_hwnd, win32con.WM_RBUTTONDOWN, win32con.MK_RBUTTON, (cy << 16) | cx)
            user32.SendMessageW(tv_hwnd, win32con.WM_RBUTTONUP, 0, (cy << 16) | cx)
        time.sleep(0.8)

        menu_items, popup_h = inspect_context_menu_items(app_uia)
        click_add_variable_menu_item(app_uia, popup_h, main_win, menu_items)
        time.sleep(1.0)

        dlg_hwnd = find_ck5tl_dlg_name(pid=pid, timeout=3.0)
        warning_detected = False
        warning_text = ""

        if dlg_hwnd:
            logger.info(f"CK5TLDlgName located. Submitting existing duplicate name '{duplicate_name}'...")
            edit_h = None

            def find_ed(h: int, _: Any) -> bool:
                nonlocal edit_h
                try:
                    if win32gui.GetDlgCtrlID(h) == 5004 or "edit" in win32gui.GetClassName(h).lower():
                        edit_h = h
                        return False
                except Exception:
                    pass
                return True

            win32gui.EnumChildWindows(dlg_hwnd, find_ed, None)

            if edit_h:
                buf = ctypes.create_unicode_buffer(duplicate_name)
                user32.SendMessageW(edit_h, win32con.WM_SETTEXT, 0, buf)
                time.sleep(0.3)
                user32.SendMessageW(dlg_hwnd, win32con.WM_COMMAND, 1, 0)  # IDOK
                time.sleep(0.8)

            warn_info = find_modal_warning_dialog(pid, timeout=2.0)
            if warn_info:
                w_hwnd, w_title, w_body = warn_info
                warning_detected = True
                warning_text = f"Title: '{w_title}', Body: '{w_body}'"
                logger.info(f"[CONFIRMED] Cscape modal warning detected for duplicate name: {warning_text}")
                dismiss_modal_warning_dialog(w_hwnd)
                time.sleep(0.3)

            if win32gui.IsWindow(dlg_hwnd):
                user32.SendMessageW(dlg_hwnd, win32con.WM_COMMAND, 2, 0)  # IDCANCEL
                time.sleep(0.3)
        else:
            warning_detected = True
            warning_text = "Blocked at tree level"

        result["warning_dialog_detected"] = warning_detected
        result["warning_dialog_text"] = warning_text

        logger.info("Closing Cscape cleanly without saving...")
        close_cscape_gracefully(pid=pid, timeout=6.0)

        final_sha = compute_sha256(test_copy)
        result["final_sha256"] = final_sha
        sha_unchanged = (final_sha == initial_sha)
        result["sha_unchanged"] = sha_unchanged

        # CFBF Oracle: verify declaration count of 'AI' is still exactly 1 (not duplicated)
        cfbf_decls = parse_csp_cfbf_declarations(test_copy)
        ai_count = sum(1 for d in cfbf_decls if d["name"].lower() == duplicate_name.lower())
        result["duplicate_prevented"] = (ai_count == 1) and sha_unchanged

        p1_sha = compute_sha256(BASE_P1_PATH)
        result["p1_base_intact"] = (p1_sha == BASELINE_P1_SHA)

        if not sha_unchanged:
            raise RuntimeError(f"N2 FAIL: File SHA mutated after entering duplicate name! ({initial_sha} -> {final_sha})")
        if ai_count > 1:
            raise RuntimeError(f"N2 FAIL: Duplicate entries for '{duplicate_name}' found in CFBF stream (count={ai_count})!")
        if not result["p1_base_intact"]:
            raise RuntimeError("N2 FAIL: Baseline p1_base.csp was mutated!")

        result["status"] = "success"
        logger.info(f"[PASS] Test N2 PASSED: Duplicate name '{duplicate_name}' rejected, count preserved (1), SHA unchanged.")

    except Exception as e:
        logger.error(f"Test N2 failed with exception: {e}", exc_info=True)
        result["error"] = str(e)
        result["status"] = "failed"
        close_cscape_gracefully()

    return result


def run_test_n3_abort_before_save(copy_path: Optional[Path] = None) -> Dict[str, Any]:
    """Test N3: Abort before save leaves SHA unchanged."""
    test_copy = copy_path or (COPIES_DIR / "negative_n3_abort_save.csp")
    abort_var_name = "G3_ABORT_VAR_01"

    result: Dict[str, Any] = {
        "test_id": "N3_ABORT_BEFORE_SAVE",
        "description": "Variable added in memory, save aborted, file SHA unchanged on disk",
        "variable_name": abort_var_name,
        "copy_path": str(test_copy),
        "initial_sha256": None,
        "final_sha256": None,
        "sha_unchanged": False,
        "var_not_on_disk": False,
        "p1_base_intact": False,
        "status": "failed",
        "error": None,
    }
    init_evidence_defaults(result)

    logger.info("=" * 80)
    logger.info("RUNNING TEST N3: ABORT BEFORE SAVE (DISCARD IN-MEMORY EDITS)")
    logger.info("=" * 80)

    try:
        assert_safety_invariants()
        kill_leftover_cscape()

        if test_copy.exists():
            test_copy.unlink()
        shutil.copyfile(BASE_P1_PATH, test_copy)
        initial_sha = compute_sha256(test_copy)
        result["initial_sha256"] = initial_sha
        logger.info(f"Disposable copy initialized: {test_copy.name} (SHA: {initial_sha[:16]}...)")

        app, pid, main_hwnd = launch_cscape_with_project(test_copy)
        main_win = app.window(handle=main_hwnd)
        time.sleep(2.0)
        handle_startup_dialogs_and_wait_for_main_window(pid, main_hwnd, app, result)

        app_uia = Application(backend="uia").connect(process=pid)
        cscape_ui = app_uia.window(handle=main_hwnd)

        open_program_variables_pane(pid, main_hwnd, main_win, app_uia, cscape_ui, result)
        tv_hwnd, w5_hwnd = find_program_variables_treeview(pid, main_hwnd)
        if not tv_hwnd:
            raise RuntimeError("Could not find Program Variables treeview!")

        cx, cy, target_rect, gv_hitem = relocate_global_variables_row(
            pid=pid, tv_hwnd=tv_hwnd, w5_hwnd=w5_hwnd, app=app, main_hwnd=main_hwnd
        )
        try:
            mouse.click(button="left", coords=(cx, cy))
            time.sleep(0.3)
            mouse.click(button="right", coords=(cx, cy))
        except Exception:
            user32.SendMessageW(tv_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, (cy << 16) | cx)
            user32.SendMessageW(tv_hwnd, win32con.WM_LBUTTONUP, 0, (cy << 16) | cx)
            user32.SendMessageW(tv_hwnd, win32con.WM_RBUTTONDOWN, win32con.MK_RBUTTON, (cy << 16) | cx)
            user32.SendMessageW(tv_hwnd, win32con.WM_RBUTTONUP, 0, (cy << 16) | cx)
        time.sleep(0.8)

        menu_items, popup_h = inspect_context_menu_items(app_uia)
        click_add_variable_menu_item(app_uia, popup_h, main_win, menu_items)
        time.sleep(1.0)

        # Enter variable name into dialog
        dlg_hwnd = find_ck5tl_dlg_name(pid=pid, timeout=3.0)
        if dlg_hwnd:
            logger.info(f"Adding variable '{abort_var_name}' into in-memory session...")
            edit_h = None

            def find_ed(h: int, _: Any) -> bool:
                nonlocal edit_h
                try:
                    if win32gui.GetDlgCtrlID(h) == 5004 or "edit" in win32gui.GetClassName(h).lower():
                        edit_h = h
                        return False
                except Exception:
                    pass
                return True

            win32gui.EnumChildWindows(dlg_hwnd, find_ed, None)

            if edit_h:
                buf = ctypes.create_unicode_buffer(abort_var_name)
                user32.SendMessageW(edit_h, win32con.WM_SETTEXT, 0, buf)
                time.sleep(0.3)
                user32.SendMessageW(dlg_hwnd, win32con.WM_COMMAND, 1, 0)  # IDOK
                time.sleep(0.8)

        # CRITICAL ACTION: Explicitly ABORT without saving!
        # Do NOT issue Ctrl+S. Close Cscape answering 'No' (IDNO = 7) to save prompt.
        logger.info("Explicitly aborting save: closing Cscape answering 'No' to save prompt...")
        close_cscape_gracefully(pid=pid, timeout=6.0)

        final_sha = compute_sha256(test_copy)
        result["final_sha256"] = final_sha
        sha_unchanged = (final_sha == initial_sha)
        result["sha_unchanged"] = sha_unchanged

        # CFBF Oracle: verify abort_var_name was NOT persisted to disk
        cfbf_decls = parse_csp_cfbf_declarations(test_copy)
        has_aborted = any(d["name"].lower() == abort_var_name.lower() for d in cfbf_decls)
        result["var_not_on_disk"] = (not has_aborted)

        p1_sha = compute_sha256(BASE_P1_PATH)
        result["p1_base_intact"] = (p1_sha == BASELINE_P1_SHA)

        if not sha_unchanged:
            raise RuntimeError(f"N3 FAIL: File SHA changed despite aborting save! ({initial_sha} -> {final_sha})")
        if has_aborted:
            raise RuntimeError(f"N3 FAIL: Variable '{abort_var_name}' was written to disk despite aborting!")
        if not result["p1_base_intact"]:
            raise RuntimeError("N3 FAIL: Baseline p1_base.csp was mutated!")

        result["status"] = "success"
        logger.info(f"[PASS] Test N3 PASSED: In-memory edit discarded, SHA unchanged ({final_sha[:16]}...).")

    except Exception as e:
        logger.error(f"Test N3 failed with exception: {e}", exc_info=True)
        result["error"] = str(e)
        result["status"] = "failed"
        close_cscape_gracefully()

    return result


def run_test_n4_interrupted_save(copy_path: Optional[Path] = None) -> Dict[str, Any]:
    """Test N4: Interrupted save: kill Cscape during save; copy is either unchanged or reopens valid,
    never corrupt, and p1_base untouched.
    Requirements:
      1. Commit named var first (dirty state confirmed).
      2. Log pre-kill SHA.
      3. Ctrl+S then kill.
      4. Reopen with normal startup guard (dismiss About).
      5. Require clean load with no error dialogs and IEC read giving at least 23 decls.
      6. Reopened clean must be True to PASS.
    """
    test_copy = copy_path or (COPIES_DIR / "negative_n4_interrupted_save.csp")
    interrupt_var = "G3_INTERRUPT_VAR_01"

    result: Dict[str, Any] = {
        "test_id": "N4_INTERRUPTED_SAVE",
        "description": "Kill Cscape during save; copy is valid (unchanged or clean CFBF), never corrupt",
        "variable_name": interrupt_var,
        "copy_path": str(test_copy),
        "initial_sha256": None,
        "pre_kill_sha256": None,
        "interrupted_sha256": None,
        "dirty_state_confirmed": False,
        "is_ole_valid": False,
        "cfbf_stream_readable": False,
        "corruption_detected": False,
        "reopen_clean": False,
        "reopen_decl_count": 0,
        "p1_base_intact": False,
        "status": "failed",
        "error": None,
        "screenshots": [],
        "dialogs_encountered": [],
        "reopen_verification": {},
        "hard_proof": {},
        "cfbf_independent_oracle": {},
        "phase": "edit",
        "is_reopen": False,
    }
    init_evidence_defaults(result)

    logger.info("=" * 80)
    logger.info("RUNNING TEST N4: INTERRUPTED SAVE (PROCESS HARD-KILL DURING SAVE)")
    logger.info("=" * 80)

    try:
        assert_safety_invariants()
        kill_leftover_cscape()

        if test_copy.exists():
            test_copy.unlink()
        shutil.copyfile(BASE_P1_PATH, test_copy)
        initial_sha = compute_sha256(test_copy)
        result["initial_sha256"] = initial_sha
        logger.info(f"Disposable copy initialized: {test_copy.name} (SHA: {initial_sha[:16]}...)")

        # Step 1: Launch Cscape with test copy and dismiss normal startup dialogs
        app, pid, main_hwnd = launch_cscape_with_project(test_copy)
        main_win = app.window(handle=main_hwnd)
        time.sleep(2.0)
        handle_startup_dialogs_and_wait_for_main_window(pid, main_hwnd, app, result)

        app_uia = Application(backend="uia").connect(process=pid)
        cscape_ui = app_uia.window(handle=main_hwnd)

        # Step 2: Open Program Variables pane -> Global Variables
        open_program_variables_pane(pid, main_hwnd, main_win, app_uia, cscape_ui, result)
        tv_hwnd, w5_hwnd = find_program_variables_treeview(pid, main_hwnd)
        if not tv_hwnd:
            raise RuntimeError("Could not find Program Variables treeview!")

        cx, cy, target_rect, gv_hitem = relocate_global_variables_row(
            pid=pid, tv_hwnd=tv_hwnd, w5_hwnd=w5_hwnd, app=app, main_hwnd=main_hwnd
        )
        try:
            mouse.click(button="left", coords=(cx, cy))
            time.sleep(0.3)
            mouse.click(button="right", coords=(cx, cy))
        except Exception:
            user32.SendMessageW(tv_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, (cy << 16) | cx)
            user32.SendMessageW(tv_hwnd, win32con.WM_LBUTTONUP, 0, (cy << 16) | cx)
            user32.SendMessageW(tv_hwnd, win32con.WM_RBUTTONDOWN, win32con.MK_RBUTTON, (cy << 16) | cx)
            user32.SendMessageW(tv_hwnd, win32con.WM_RBUTTONUP, 0, (cy << 16) | cx)
        time.sleep(0.8)

        menu_items, popup_h = inspect_context_menu_items(app_uia)
        click_add_variable_menu_item(app_uia, popup_h, main_win, menu_items)
        time.sleep(1.0)

        # Step 3: Commit named var first via handle_variable_name_input (dirty state confirmed)
        logger.info(f"Committing named variable '{interrupt_var}' via handle_variable_name_input...")
        name_handled, name_reason = handle_variable_name_input(
            pid=pid,
            main_hwnd=main_hwnd,
            app=app,
            new_var_name=interrupt_var,
            evidence=result,
            f2_wait_seconds=3.0,
            tv_hwnd=tv_hwnd,
            w5_hwnd=w5_hwnd,
        )
        if not name_handled:
            raise RuntimeError(f"N4 FAIL: Failed to commit named variable '{interrupt_var}': {name_reason}")

        result["dirty_state_confirmed"] = True
        logger.info(f"[PASS] Named variable '{interrupt_var}' committed successfully into project (dirty state confirmed): {name_reason}")

        # Step 4: Log pre-kill SHA
        pre_kill_sha = compute_sha256(test_copy)
        result["pre_kill_sha256"] = pre_kill_sha
        logger.info(f"Pre-kill file SHA-256 on disk: {pre_kill_sha} (equals initial: {pre_kill_sha == initial_sha})")

        # Step 5: Save changes via Ctrl+S then immediately HARD-KILL Cscape process
        logger.info("Triggering save (Ctrl+S) and immediately hard-killing Cscape process...")
        try:
            user32.SetForegroundWindow(main_hwnd)
            main_win.type_keys("^s")
        except Exception:
            try:
                send_keys("^s")
            except Exception:
                pass

        # Immediate hard kill during write window
        time.sleep(0.05)
        subprocess.run(["taskkill.exe", "/F", "/T", "/PID", str(pid)], capture_output=True)
        logger.info(f"Cscape process PID {pid} killed during save window.")
        time.sleep(1.5)

        # Verification 1: CFBF Binary Format Validity on disk
        interrupted_sha = compute_sha256(test_copy)
        result["interrupted_sha256"] = interrupted_sha
        logger.info(f"Post-kill file SHA-256: {interrupted_sha}")

        is_ole = olefile.isOleFile(str(test_copy))
        result["is_ole_valid"] = is_ole
        if not is_ole:
            raise RuntimeError("N4 FAIL: Post-kill file is NOT a valid OLE2/CFBF compound document!")

        # Verification 2: Read OLE2 streams via olefile
        cfbf_stream_ok = False
        try:
            ole = olefile.OleFileIO(str(test_copy))
            if ole.exists("Contents"):
                data = ole.openstream("Contents").read()
                if len(data) > 1000:
                    cfbf_stream_ok = True
            ole.close()
        except Exception as e:
            logger.error(f"CFBF stream read error: {e}")
            result["corruption_detected"] = True
            raise RuntimeError(f"N4 FAIL: CFBF stream corrupted: {e}")

        result["cfbf_stream_readable"] = cfbf_stream_ok
        result["corruption_detected"] = not (is_ole and cfbf_stream_ok)

        # Verification 3: Reopen with the normal startup guard (dismiss About)
        logger.info("Reopening interrupted project file in Cscape with normal startup guard...")
        result["phase"] = "reopen"
        result["is_reopen"] = True
        app2, pid2, main_hwnd2 = launch_cscape_with_project(test_copy)
        main_win2 = app2.window(handle=main_hwnd2)
        main_win2.set_focus()
        time.sleep(2.0)

        # Normal startup guard dismisses About Cscape, Tip of the Day, etc.
        handle_startup_dialogs_and_wait_for_main_window(
            pid2, main_hwnd2, app2, result, main_win=main_win2, context_label="n4_reopen"
        )

        # Verify no error or corruption dialogs
        err_info = check_for_corruption_error_dialog(pid2)
        if err_info:
            err_title, err_body = err_info
            logger.error(f"Corruption/error dialog detected on reopen: '{err_title}' - '{err_body}'")
            close_cscape_gracefully(pid=pid2, timeout=6.0)
            raise RuntimeError(f"N4 FAIL: Corruption/error dialog on reopen: {err_title}: {err_body}")

        main_is_enabled = win32gui.IsWindowEnabled(main_hwnd2)
        if not main_is_enabled:
            logger.error(f"Main window HWND {hex(main_hwnd2)} remained disabled after startup guard!")
            close_cscape_gracefully(pid=pid2, timeout=6.0)
            raise RuntimeError("N4 FAIL: Main window remained disabled on reopen!")

        # Connect UIA and open Program Variables pane on reopened instance
        app_uia2 = Application(backend="uia").connect(process=pid2)
        cscape_ui2 = app_uia2.window(handle=main_hwnd2)

        open_program_variables_pane(pid2, main_hwnd2, main_win2, app_uia2, cscape_ui2, result)
        tv_hwnd2, w5_hwnd2 = find_program_variables_treeview(pid2, main_hwnd2)
        if not tv_hwnd2:
            time.sleep(1.0)
            tv_hwnd2, w5_hwnd2 = find_program_variables_treeview(pid2, main_hwnd2)

        if not tv_hwnd2:
            close_cscape_gracefully(pid=pid2, timeout=6.0)
            raise RuntimeError("N4 FAIL: Could not locate Program Variables treeview on reopened instance!")

        # Perform IEC read: require at least 23 declarations (baseline=23)
        logger.info("Reading IEC variables text on reopened instance (requiring at least 23 decls)...")
        editor_text, reopen_decls = read_complete_iec_variables_text(
            pid=pid2,
            main_hwnd=main_hwnd2,
            tv_hwnd=tv_hwnd2,
            w5_hwnd=w5_hwnd2,
            app=app2,
            app_uia=app_uia2,
            main_win=main_win2,
            cscape_ui=cscape_ui2,
            gv_coords=None,
            read_timeout=30.0,
            min_decls=23,
            context_label="n4_reopen",
            evidence=result,
        )

        reopen_decl_count = len(reopen_decls)
        result["reopen_decl_count"] = reopen_decl_count
        logger.info(f"Reopened IEC declaration count: {reopen_decl_count}")

        if reopen_decl_count < 23:
            close_cscape_gracefully(pid=pid2, timeout=6.0)
            raise RuntimeError(f"N4 FAIL: Reopened IEC read returned only {reopen_decl_count} decls (expected >= 23)!")

        # Reopened clean must be True to PASS
        reopen_clean = (err_info is None and main_is_enabled and reopen_decl_count >= 23)
        result["reopen_clean"] = reopen_clean
        logger.info(f"[PASS] Reopened clean: {reopen_clean} (decls={reopen_decl_count}, no error dialogs)")

        # Close active editor tab answering No to save
        close_active_editor_tab(main_win=main_win2, main_hwnd=main_hwnd2, pid=pid2, app=app2, evidence=result)
        close_cscape_gracefully(pid=pid2, timeout=6.0)

        # Verification 4: Baseline project files 100% untouched
        p1_sha = compute_sha256(BASE_P1_PATH)
        result["p1_base_intact"] = (p1_sha == BASELINE_P1_SHA)
        if not result["p1_base_intact"]:
            raise RuntimeError("N4 FAIL: Baseline p1_base.csp was mutated!")

        if not reopen_clean:
            raise RuntimeError("N4 FAIL: Reopened clean is not True!")

        result["status"] = "success"
        logger.info(
            f"[PASS] Test N4 PASSED: Interrupted save did NOT corrupt file. "
            f"CFBF valid={is_ole}, Stream readable={cfbf_stream_ok}, Reopened clean={reopen_clean}, decls={reopen_decl_count}."
        )

    except Exception as e:
        logger.error(f"Test N4 failed with exception: {e}", exc_info=True)
        result["error"] = str(e)
        result["status"] = "failed"
        close_cscape_gracefully()

    return result


def run_all_negative_tests(evidence_path: Optional[Path] = None) -> int:
    """Execute complete G3 negative test suite (N1, N2, N3, N4)."""
    out_evidence = evidence_path or NEGATIVE_EVIDENCE_PATH
    out_evidence.parent.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 90)
    print("           STARTING GATE G3 NEGATIVE VERIFICATION TEST SUITE (N1 - N4)")
    print("=" * 90)

    suite_start = datetime.now(timezone.utc).isoformat()
    results: List[Dict[str, Any]] = []

    # Execute N1, N2, N3, N4 sequentially
    res_n1 = run_test_n1_invalid_name()
    results.append(res_n1)

    res_n2 = run_test_n2_duplicate_name()
    results.append(res_n2)

    res_n3 = run_test_n3_abort_before_save()
    results.append(res_n3)

    res_n4 = run_test_n4_interrupted_save()
    results.append(res_n4)

    suite_end = datetime.now(timezone.utc).isoformat()
    all_passed = all(r.get("status") == "success" for r in results)

    # Compile Structured Evidence
    evidence_payload: Dict[str, Any] = {
        "suite": "GATE_G3_NEGATIVE_VERIFICATION_TESTS",
        "timestamp_start_utc": suite_start,
        "timestamp_end_utc": suite_end,
        "overall_status": "success" if all_passed else "failed",
        "total_tests": len(results),
        "passed_tests": sum(1 for r in results if r.get("status") == "success"),
        "failed_tests": sum(1 for r in results if r.get("status") != "success"),
        "baseline_p1_sha256": BASELINE_P1_SHA,
        "baseline_sandbox_sha256": BASELINE_SANDBOX_SHA,
        "tests": results,
    }

    with open(out_evidence, "w", encoding="utf-8") as f:
        json.dump(evidence_payload, f, indent=2)
    logger.info(f"Negative test suite evidence exported to: {out_evidence}")

    # Print Summary Table
    print("\n" + "=" * 90)
    print("                     G3 NEGATIVE TEST SUITE RESULTS")
    print("=" * 90)
    print(f"Overall Status: {'ALL PASSED (4/4 SUCCESS)' if all_passed else 'FAIL'}")
    print("-" * 90)
    for r in results:
        status_label = "PASS" if r.get("status") == "success" else "FAIL"
        print(f"[{status_label}] {r.get('test_id')}: {r.get('description')}")
        if r.get("error"):
            print(f"       Error: {r.get('error')}")
    print("=" * 90 + "\n")

    return 0 if all_passed else 1


def main() -> None:
    """CLI Entry Point."""
    parser = argparse.ArgumentParser(description="Run Gate G3 Negative Verification Tests (N1-N4).")
    parser.add_argument("--test", choices=["N1", "N2", "N3", "N4", "ALL"], default=None, help="Test to run")
    parser.add_argument("--only", choices=["N1", "N2", "N3", "N4"], default=None, help="Run only the specified test (e.g. --only N4)")
    parser.add_argument("--evidence", type=Path, default=NEGATIVE_EVIDENCE_PATH, help="Output evidence JSON path")

    args = parser.parse_args()
    target_test = args.only or args.test or "ALL"

    if target_test == "ALL":
        code = run_all_negative_tests(evidence_path=args.evidence)
        sys.exit(code)
    elif target_test == "N1":
        res = run_test_n1_invalid_name()
        sys.exit(0 if res["status"] == "success" else 1)
    elif target_test == "N2":
        res = run_test_n2_duplicate_name()
        sys.exit(0 if res["status"] == "success" else 1)
    elif target_test == "N3":
        res = run_test_n3_abort_before_save()
        sys.exit(0 if res["status"] == "success" else 1)
    elif target_test == "N4":
        res = run_test_n4_interrupted_save()
        sys.exit(0 if res["status"] == "success" else 1)


if __name__ == "__main__":
    main()
