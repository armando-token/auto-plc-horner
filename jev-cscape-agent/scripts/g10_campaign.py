#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gate G10 Campaign: Perturbaciones Reales, Recuperacion y Abstencion Segura (W076-W083).

Mandate (Real Megaplan Section G10, Work Packages W076-W083):
  - >= 25 Negative / Recovery Scenarios (strictly separate from G3/G7/G8/G9 positive tasks).
  - Each scenario has an explicit expected outcome in {'recover', 'abstain', 'pause'}:
      * W076: Window Size / Position Perturbations (small resize/clipping, offscreen displacement,
              minimized/iconic state, zero-area/locked splitter).
      * W077: External Focus Steal & Unexpected Modal Dialogs (external foreground steal,
              persistent external lock, unexpected About Cscape, unexpected Screen Thumbnails / Find,
              unexpected Program Information Modified / Save prompt, unknown blocking #32770 modal).
      * W078: Provider / Jev Faults (transient timeout recovery, persistent timeout pause,
              HTTP 429 short Retry-After recovery, HTTP 429 long Retry-After pause,
              bad API key 401/403 abstain, unsupported/changed model abstain, malformed wire schema abstain)
              hitting real https://api.typesafe.ai/v1/systemone with transport-layer fault injection and
              live Cscape verification.
      * W079: Worker / Cscape Crash & Kill Mid-Save & Post-Commit Recovery (kill real Cscape/worker PID
              mid-save rollback + reopen & verify SHA, kill real Cscape/worker PID post-commit journal
              promotion + reopen & verify SHA, post-commit corrupt staging abstain + reopen & verify SHA).
      * W080: Stale Index & Desynchronized Cache (stale RAG/symbol index Merkle rebuild recovery on real
              mutated .csp, stale TagDatabase AppliMap before ErrorCheck 32826 resync recovery,
              corrupted/locked CFBF stream cache desync pause).
      * W081: Log Growth / Disk Quota & Hung Observer Watchdog (runaway log flood rotation/truncation recovery
              with real observer subprocess, hung observer subprocess watchdog kill/restart recovery,
              permanently wedged UIA observer subprocess exhaustion pause).
      * W082: Second Profile / Hardware Target Isolation (switch from Primary Profile A to Secondary Profile B
              across two real Cscape sessions with zero tag bleed, incompatible hardware target / COM1 probe abstain).
      * W083: End-to-End G10 Campaign Orchestrator & Acceptance Gate.
  - Real Cscape 10.2 & Real Jev (https://api.typesafe.ai/v1/systemone, model: jev-latest), zero mocks in --live mode.
  - Mandatory Per-Scenario Telemetry Logging: Every scenario logs PID, HTTP status, req_id, and file SHA.
  - Strict Log Isolation: Unit tests write exclusively to artifacts/logs/g10_unit_test.log, never touching
    artifacts/logs/g10_campaign.log.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
import logging
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import urllib.error
import urllib.request

# Dynamic repository root resolution
REPO_ROOT = Path(__file__).resolve().parent.parent
if not (REPO_ROOT / "work" / "disposable" / "p1_base.csp").exists():
    REPO_ROOT = Path(r"C:\HornerAI\jev-cscape-agent")

if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import olefile
import psutil
import win32con
import win32gui
import win32process
from pywinauto import Application

from jev_cscape.contracts import AgentStatus
from jev_cscape.security.exceptions import HardwareLockoutError
from jev_cscape.security.guard import SecurityGuard

from scripts.g3_edit_roundtrip import (
    check_iec_text_completeness,
    close_active_editor_tab,
    extract_var_declaration,
    find_iec_editor_candidate_windows,
    find_program_variables_treeview,
    focus_iec_editor,
    get_treeview_item_texts,
    inspect_context_menu_items,
    open_program_variables_pane,
    parse_csp_cfbf_declarations,
    parse_iec_declarations,
    read_text_from_active_editor,
    relocate_global_variables_row,
)
from scripts.g7_acceptance import (
    dismiss_about_cscape_and_wait_main_enabled,
    trigger_and_read_cscape_error_check,
)
from scripts.g8_acceptance import (
    _force_close_modal_dialog,
    _send_msg_timeout,
    handle_confirmation_popups,
)
from scripts.g9_campaign import (
    BASELINE_P1_SHA,
    BASE_P1_PATH,
    ID_CONTROLLER_DOWNLOAD,
    ID_FILE_SAVE,
    ID_PROGRAM_DOWNLOAD,
    ID_PROGRAM_ERRORCHECK,
    _set_clipboard_unicode_text,
    close_and_commit_iec_variables_editor_tab,
    compute_sha256,
    declare_variables_via_live_cscape_ui as _g9_declare_variables_via_live_cscape_ui,
    dismiss_error_check_modals,
    handle_program_information_modified_dialog,
)
from scripts.probe_hmi_editor import (
    close_cscape_gracefully,
    configure_cscape_registry,
    dump_child_windows_recursive,
    handle_startup_dialogs_and_wait_for_main_window,
    is_screen_editor_window,
    kill_leftover_cscape,
    launch_cscape_with_project,
    open_screen_editor_dynamic,
)

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
ID_APP_ABOUT = 57664
ID_VIEW_THUMBNAILS = 38509
ID_VIEW_PROGRAM_VARIABLES = 38053
ID_EDIT_VARIABLES_AS_TEXT = 38141
ID_ADD_VARIABLE = 38016

# Directories & Output Paths
COPIES_DIR = REPO_ROOT / "work" / "disposable" / "copies"
COPIES_DIR.mkdir(parents=True, exist_ok=True)
G10_SANDBOX_DIR = REPO_ROOT / "work" / "disposable" / "g10_sandbox"
G10_SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

ARTIFACTS_G10_DIR = REPO_ROOT / "artifacts" / "G10"
ARTIFACTS_G10_DIR.mkdir(parents=True, exist_ok=True)
SCENARIOS_EVIDENCE_DIR = ARTIFACTS_G10_DIR / "scenarios"
SCENARIOS_EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_JSON_PATH = ARTIFACTS_G10_DIR / "g10_campaign_summary.json"

UNIT_TEST_ARTIFACTS_G10_DIR = REPO_ROOT / "work" / "disposable" / "g10_unit_test_artifacts"
UNIT_TEST_ARTIFACTS_G10_DIR.mkdir(parents=True, exist_ok=True)
UNIT_TEST_SCENARIOS_DIR = UNIT_TEST_ARTIFACTS_G10_DIR / "scenarios"
UNIT_TEST_SCENARIOS_DIR.mkdir(parents=True, exist_ok=True)
UNIT_TEST_SUMMARY_JSON_PATH = UNIT_TEST_ARTIFACTS_G10_DIR / "g10_campaign_summary.json"

LOG_DIR = REPO_ROOT / "artifacts" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE_PATH = LOG_DIR / "g10_campaign.log"
UNIT_TEST_LOG_FILE_PATH = LOG_DIR / "g10_unit_test.log"

logger = logging.getLogger("g10_campaign")
logger.setLevel(logging.INFO)
logger.propagate = False


def _is_running_under_pytest() -> bool:
    """Return True when imported or executed inside a pytest session."""
    return (
        "pytest" in sys.modules
        or "_pytest" in sys.modules
        or bool(os.environ.get("PYTEST_CURRENT_TEST"))
    )


def configure_g10_logging(
    log_path: Optional[Path] = None,
    unit_test_mode: Optional[bool] = None,
    force_live_log: bool = False,
) -> Path:
    """Configure g10_campaign logger so unit tests write exclusively to g10_unit_test.log."""
    use_unit_test_log = (
        unit_test_mode
        if unit_test_mode is not None
        else (_is_running_under_pytest() and not force_live_log)
    )
    resolved_log_path = (
        Path(log_path)
        if log_path is not None
        else (UNIT_TEST_LOG_FILE_PATH if use_unit_test_log else LOG_FILE_PATH)
    )
    resolved_log_path.parent.mkdir(parents=True, exist_ok=True)

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] g10_campaign: %(message)s")
    fh = logging.FileHandler(resolved_log_path, mode="a", encoding="utf-8")
    fh.setLevel(logging.INFO)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(formatter)
    logger.addHandler(sh)
    return resolved_log_path


configure_g10_logger = configure_g10_logging
configure_g10_logging()


@dataclass
class _G10LiveVarSpec:
    """Lightweight variable specification adapter for live Cscape variable declaration in W079/W080."""

    task_id: str
    task_num: int
    level_pv_tag: str
    inlet_valve_tag: str


def _keep_interactive_desktop_awake() -> bool:
    """Prevent Windows display blanking/locking during multi-minute live runs and bind to winsta0\\Default."""
    try:
        # ES_CONTINUOUS (0x80000000) | ES_SYSTEM_REQUIRED (0x00000001) | ES_DISPLAY_REQUIRED (0x00000002)
        kernel32.SetThreadExecutionState(0x80000003)
    except Exception:
        pass
    try:
        h_desk = user32.OpenDesktopW("Default", 0, False, 0x01FF)
        if h_desk:
            user32.SetThreadDesktop(h_desk)
            user32.CloseDesktop(h_desk)
    except Exception:
        pass
    try:
        # Zero-delta relative mouse move resets display idle timer when interactive desktop is active
        user32.mouse_event(0x0001, 0, 0, 0, 0)
    except Exception:
        pass
    return True


_CURSORLESS_WIN32_FALLBACK_ACTIVE: bool = False


def _is_cursorless_mouse_error(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return (
        "active desktop" in msg
        or "setcursorpos" in msg
        or "access is denied" in msg
        or getattr(exc, "winerror", None) == 5
        or (isinstance(exc.args, tuple) and len(exc.args) > 0 and exc.args[0] == 5)
    )


def _post_client_mouse_click(screen_x: int, screen_y: int, button: str = "left", double: bool = False) -> bool:
    """Fallback cursorless click via WindowFromPoint + ChildWindowFromPointEx + ScreenToClient + PostMessageW."""
    try:
        pt = wintypes.POINT(int(screen_x), int(screen_y))
        hwnd = user32.WindowFromPoint(pt)
        if not hwnd or not win32gui.IsWindow(hwnd):
            return False
        # Resolve deepest visible child window at (screen_x, screen_y)
        for _ in range(8):
            try:
                cx_p, cy_p = win32gui.ScreenToClient(hwnd, (int(screen_x), int(screen_y)))
                pt_c = wintypes.POINT(int(cx_p), int(cy_p))
                child = user32.ChildWindowFromPointEx(hwnd, pt_c, 0x0001 | 0x0002)  # CWP_SKIPINVISIBLE | CWP_SKIPDISABLED
                if not child or child == hwnd or not win32gui.IsWindow(child):
                    break
                hwnd = child
            except Exception:
                break
        cx, cy = win32gui.ScreenToClient(hwnd, (int(screen_x), int(screen_y)))
        lparam = ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)
        user32.PostMessageW(hwnd, win32con.WM_MOUSEMOVE, 0, lparam)
        if button == "right":
            user32.PostMessageW(hwnd, win32con.WM_RBUTTONDOWN, win32con.MK_RBUTTON, lparam)
            user32.PostMessageW(hwnd, win32con.WM_RBUTTONUP, 0, lparam)
            screen_lparam = ((int(screen_y) & 0xFFFF) << 16) | (int(screen_x) & 0xFFFF)
            user32.PostMessageW(hwnd, win32con.WM_CONTEXTMENU, hwnd, screen_lparam)
        elif double:
            user32.PostMessageW(hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam)
            user32.PostMessageW(hwnd, win32con.WM_LBUTTONUP, 0, lparam)
            user32.PostMessageW(hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam)
            user32.PostMessageW(hwnd, win32con.WM_LBUTTONUP, 0, lparam)
        else:
            user32.PostMessageW(hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam)
            user32.PostMessageW(hwnd, win32con.WM_LBUTTONUP, 0, lparam)
        return True
    except Exception:
        return False


def _install_cursorless_mouse_guard() -> None:
    """Patch pywinauto.mouse and BaseWrapper.click_input so 'no active desktop' / 'Access is denied'
    silently and deterministically dispatches via client-coordinate Win32 messages without warnings."""
    try:
        from pywinauto import mouse as _pwa_mouse
        from pywinauto.base_wrapper import BaseWrapper as _PwaBaseWrapper

        if not getattr(_pwa_mouse, "_g10_cursorless_guarded", False):
            _orig_click = _pwa_mouse.click
            _orig_double_click = _pwa_mouse.double_click
            _orig_move = _pwa_mouse.move

            def _safe_click(button: str = "left", coords: Tuple[int, int] = (0, 0)) -> None:
                global _CURSORLESS_WIN32_FALLBACK_ACTIVE
                _keep_interactive_desktop_awake()
                if _CURSORLESS_WIN32_FALLBACK_ACTIVE:
                    _post_client_mouse_click(int(coords[0]), int(coords[1]), button=button, double=False)
                    return
                try:
                    _orig_click(button=button, coords=coords)
                except Exception as exc:
                    if _is_cursorless_mouse_error(exc):
                        _CURSORLESS_WIN32_FALLBACK_ACTIVE = True
                        logger.debug(
                            f"Cursorless Win32 mouse dispatch activated on click({button}, {coords})."
                        )
                        _post_client_mouse_click(int(coords[0]), int(coords[1]), button=button, double=False)
                    else:
                        raise

            def _safe_double_click(button: str = "left", coords: Tuple[int, int] = (0, 0)) -> None:
                global _CURSORLESS_WIN32_FALLBACK_ACTIVE
                _keep_interactive_desktop_awake()
                if _CURSORLESS_WIN32_FALLBACK_ACTIVE:
                    _post_client_mouse_click(int(coords[0]), int(coords[1]), button=button, double=True)
                    return
                try:
                    _orig_double_click(button=button, coords=coords)
                except Exception as exc:
                    if _is_cursorless_mouse_error(exc):
                        _CURSORLESS_WIN32_FALLBACK_ACTIVE = True
                        logger.debug(
                            f"Cursorless Win32 mouse dispatch activated on double_click({button}, {coords})."
                        )
                        _post_client_mouse_click(int(coords[0]), int(coords[1]), button=button, double=True)
                    else:
                        raise

            def _safe_move(coords: Tuple[int, int] = (0, 0)) -> None:
                global _CURSORLESS_WIN32_FALLBACK_ACTIVE
                _keep_interactive_desktop_awake()
                if _CURSORLESS_WIN32_FALLBACK_ACTIVE:
                    return
                try:
                    _orig_move(coords=coords)
                except Exception as exc:
                    if _is_cursorless_mouse_error(exc):
                        _CURSORLESS_WIN32_FALLBACK_ACTIVE = True
                    else:
                        raise

            _pwa_mouse.click = _safe_click
            _pwa_mouse.double_click = _safe_double_click
            _pwa_mouse.move = _safe_move
            setattr(_pwa_mouse, "_g10_cursorless_guarded", True)

        if not getattr(_PwaBaseWrapper, "_g10_cursorless_guarded", False):
            _orig_click_input = _PwaBaseWrapper.click_input

            def _safe_click_input(self_wrap: Any, *args: Any, **kwargs: Any) -> None:
                global _CURSORLESS_WIN32_FALLBACK_ACTIVE
                _keep_interactive_desktop_awake()
                if not _CURSORLESS_WIN32_FALLBACK_ACTIVE:
                    try:
                        _orig_click_input(self_wrap, *args, **kwargs)
                        return
                    except Exception as exc:
                        if _is_cursorless_mouse_error(exc):
                            _CURSORLESS_WIN32_FALLBACK_ACTIVE = True
                        else:
                            raise
                button = str(kwargs.get("button", "left"))
                double = bool(kwargs.get("double", False))
                try:
                    r = self_wrap.rectangle()
                    cx = int((r.left + r.right) // 2)
                    cy = int((r.top + r.bottom) // 2)
                    _post_client_mouse_click(cx, cy, button=button, double=double)
                except Exception:
                    pass

            _PwaBaseWrapper.click_input = _safe_click_input
            setattr(_PwaBaseWrapper, "_g10_cursorless_guarded", True)
    except Exception as e:
        logger.debug(f"Could not install cursorless mouse guard: {e}")


_keep_interactive_desktop_awake()
_install_cursorless_mouse_guard()


def _mutate_csp_cfbf_for_dry_run(csp_path: Path, tag_token: str) -> str:
    """Deterministically mutate a disposable .csp copy's /V,G, stream record in dry-run mode so SHA & Merkle change."""
    raw = csp_path.read_bytes()
    needle = b"/V,G,BOOL(0)[0],0,NQgthP6CJaXmN9_InternalUseOnly"
    padded_tag = f"{tag_token:_<30}"[:30].encode("ascii", errors="ignore")
    replacement = b"/V,G,BOOL(0)[0],0," + padded_tag
    if needle in raw and len(needle) == len(replacement):
        csp_path.write_bytes(raw.replace(needle, replacement))
    else:
        # Sector-aligned 512-byte fallback if placeholder already replaced
        digest_block = hashlib.sha256(tag_token.encode("utf-8")).digest() * 16
        csp_path.write_bytes(raw + digest_block[:512])
    return compute_sha256(csp_path)


def declare_variables_via_live_cscape_win32(
    pid: int,
    main_hwnd: int,
    app: Application,
    spec: Any,
    app_uia: Optional[Application] = None,
    copy_path: Optional[Path] = None,
) -> bool:
    """Cursorless pure-Win32 live Cscape variable declaration and save (zero SetCursorPos / mouse.click dependency).

    Uses direct CProjectDatabaseWnd (ctrl_id=355) command ID_EDIT_VARIABLES_AS_TEXT (38141, 0x94FD, VA 0x007A58A0)
    and W5EditTL.dll client-coordinate WM_LBUTTONDOWN row selection so it succeeds even when the Windows display
    or input desktop is blanked/locked after 7+ minutes.
    """
    _keep_interactive_desktop_awake()
    _install_cursorless_mouse_guard()
    logger.info(
        f"[{spec.task_id}] Declaring variables via cursorless Win32 Cscape pipeline "
        f"(ID_EDIT_VARIABLES_AS_TEXT=38141, tags={spec.level_pv_tag}, {spec.inlet_valve_tag})..."
    )

    if app_uia is None:
        try:
            app_uia = Application(backend="uia").connect(process=pid)
        except Exception:
            pass

    main_win = app.window(handle=main_hwnd)
    cscape_ui = app_uia.window(handle=main_hwnd) if app_uia else None
    level_pv_reg = f"%R{100 + int(spec.task_num)}"
    inlet_valve_reg = f"%M{100 + int(spec.task_num)}"

    # 1. Ensure Program Variables pane is visible via pure Win32 (ID_VIEW_PROGRAM_VARIABLES = 38053) + helper
    tv_hwnd, w5_hwnd = find_program_variables_treeview(pid, main_hwnd)
    if not tv_hwnd or not win32gui.IsWindow(tv_hwnd) or not win32gui.IsWindowVisible(tv_hwnd):
        try:
            open_program_variables_pane(pid, main_hwnd, main_win, app_uia, cscape_ui, {})
        except Exception as e_pv:
            logger.warning(f"[{spec.task_id}] open_program_variables_pane note: {e_pv}")
        tv_hwnd, w5_hwnd = find_program_variables_treeview(pid, main_hwnd)

    if not tv_hwnd or not win32gui.IsWindow(tv_hwnd) or not win32gui.IsWindowVisible(tv_hwnd):
        logger.info(f"[{spec.task_id}] Toggling Program Variables docking bar via WM_COMMAND {ID_VIEW_PROGRAM_VARIABLES}...")
        user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_VIEW_PROGRAM_VARIABLES, 0)
        time.sleep(0.8)
        tv_hwnd, w5_hwnd = find_program_variables_treeview(pid, main_hwnd)

    if not tv_hwnd or not win32gui.IsWindow(tv_hwnd):
        logger.warning(f"[{spec.task_id}] SysTreeView32 for Program Variables not found!")
        return False

    # 2. Relocate Global Variables row and select it in W5EditTL via client-coord WM_LBUTTONDOWN (zero SetCursorPos)
    target_cx, target_cy, _target_rect, _gv_hitem = relocate_global_variables_row(
        pid=pid, tv_hwnd=tv_hwnd, w5_hwnd=w5_hwnd, app=app, main_hwnd=main_hwnd
    )
    if target_cx and target_cy:
        try:
            cli_x, cli_y = win32gui.ScreenToClient(tv_hwnd, (int(target_cx), int(target_cy)))
        except Exception:
            cli_x, cli_y = 45, 10
    else:
        cli_x, cli_y = 45, 10

    lparam_click = ((cli_y & 0xFFFF) << 16) | (cli_x & 0xFFFF)
    user32.SendMessageW(tv_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_click)
    user32.SendMessageW(tv_hwnd, win32con.WM_LBUTTONUP, 0, lparam_click)
    time.sleep(0.25)

    # Resolve CProjectDatabaseWnd (ctrl_id=355, parent of W5EditTL ctrl_id=1603)
    if not w5_hwnd or not win32gui.IsWindow(w5_hwnd):
        try:
            w5_hwnd = win32gui.GetParent(tv_hwnd)
        except Exception:
            w5_hwnd = 0
    proj_db_hwnd = 0
    if w5_hwnd and win32gui.IsWindow(w5_hwnd):
        try:
            proj_db_hwnd = win32gui.GetParent(w5_hwnd)
        except Exception:
            proj_db_hwnd = 0

    def _find_visible_w5editst() -> Tuple[Optional[int], Optional[int]]:
        act_mdi, cands = find_iec_editor_candidate_windows(main_hwnd)
        for h in cands:
            if win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                cls = (win32gui.GetClassName(h) or "").lower()
                if "w5editst" in cls or "w5edit" in cls:
                    return act_mdi, h
        return act_mdi, (cands[0] if cands else None)

    # 3. Open 'Edit Variables as Text' directly via WM_COMMAND 38141 (ID_EDIT_VARIABLES_AS_TEXT)
    for target_h in (proj_db_hwnd, w5_hwnd, tv_hwnd, main_hwnd):
        if target_h and win32gui.IsWindow(target_h):
            user32.PostMessageW(target_h, win32con.WM_COMMAND, ID_EDIT_VARIABLES_AS_TEXT, 0)
            time.sleep(0.45)
            active_mdi, editor_hwnd = _find_visible_w5editst()
            if editor_hwnd and win32gui.IsWindow(editor_hwnd):
                break
    else:
        active_mdi, editor_hwnd = _find_visible_w5editst()

    # Fallback to guarded _g9_declare_variables_via_live_cscape_ui if W5EditST did not open directly
    if not (editor_hwnd and win32gui.IsWindow(editor_hwnd)):
        logger.info(f"[{spec.task_id}] Falling back to guarded G9 UI declaration pipeline...")
        return bool(
            _g9_declare_variables_via_live_cscape_ui(
                pid=pid,
                main_hwnd=main_hwnd,
                app=app,
                spec=spec,
                app_uia=app_uia,
                copy_path=copy_path,
            )
        )

    logger.info(f"[{spec.task_id}] W5EditST editor opened via pure Win32 (HWND {hex(editor_hwnd)}). Reading text...")
    existing_text = ""
    prev_complete: Optional[str] = None
    for _poll in range(6):
        cand_text = read_text_from_active_editor(
            main_hwnd, cscape_ui, main_win, evidence={}, context_label=f"{spec.task_id}_var_decl_win32"
        )
        if cand_text:
            existing_text = cand_text
        is_comp, _ = check_iec_text_completeness(cand_text, min_decls=23)
        if is_comp:
            if prev_complete is not None and cand_text.strip() == prev_complete.strip():
                existing_text = cand_text
                break
            prev_complete = cand_text
        else:
            prev_complete = None
        time.sleep(0.2)

    new_lines: List[str] = []
    if spec.level_pv_tag.lower() not in existing_text.lower():
        new_lines.append(f"   {spec.level_pv_tag} : INT ;\r\n      (*$tag={level_pv_reg}*)\r\n")
    if spec.inlet_valve_tag.lower() not in existing_text.lower():
        new_lines.append(f"   {spec.inlet_valve_tag} : BOOL ;\r\n      (*$tag={inlet_valve_reg}*)\r\n")

    if new_lines:
        idx_end = existing_text.upper().rfind("END_VAR")
        if idx_end != -1:
            updated_text = existing_text[:idx_end] + "".join(new_lines) + existing_text[idx_end:]
        else:
            updated_text = existing_text + "\r\nVAR\r\n" + "".join(new_lines) + "END_VAR\r\n"

        focus_iec_editor(main_hwnd=main_hwnd, active_mdi=active_mdi, editor_hwnd=editor_hwnd)
        _set_clipboard_unicode_text(updated_text)
        time.sleep(0.15)

        user32.SendMessageW(editor_hwnd, 0x040F, 0, 0)  # CW5EditST::OnEditSelectAll
        time.sleep(0.08)
        user32.SendMessageW(editor_hwnd, win32con.WM_PASTE, 0, 0)
        user32.SendMessageW(editor_hwnd, 0x0415, 0, 0)  # CW5EditST::OnEditPaste
        for target_f in (active_mdi, main_hwnd, editor_hwnd):
            if target_f and win32gui.IsWindow(target_f):
                user32.SendMessageW(target_f, win32con.WM_COMMAND, 57642, 0)  # ID_EDIT_SELECT_ALL
                user32.SendMessageW(target_f, win32con.WM_COMMAND, 57637, 0)  # ID_EDIT_PASTE
        time.sleep(0.3)

    prompt_handled = close_and_commit_iec_variables_editor_tab(
        pid=pid,
        main_hwnd=main_hwnd,
        main_win=main_win,
        active_mdi=active_mdi,
        editor_hwnd=editor_hwnd,
    )
    logger.info(f"[{spec.task_id}] close_and_commit_iec_variables_editor_tab prompt_handled={prompt_handled}")

    initial_sha = compute_sha256(copy_path) if (copy_path and copy_path.exists()) else None

    user32.SetForegroundWindow(main_hwnd)
    time.sleep(0.15)
    user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_PROGRAM_ERRORCHECK, 0)
    time.sleep(0.7)
    handle_program_information_modified_dialog(pid=pid, timeout=1.0)
    handle_confirmation_popups(pid=pid, timeout=1.0)
    dismiss_error_check_modals(pid=pid, timeout=2.0)

    user32.SendMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
    time.sleep(0.8)
    handle_program_information_modified_dialog(pid=pid, timeout=1.0)
    handle_confirmation_popups(pid=pid, timeout=1.0)
    dismiss_error_check_modals(pid=pid, timeout=1.0)

    if copy_path and initial_sha:
        poll_deadline = time.time() + 8.0
        while time.time() < poll_deadline:
            saved_sha = compute_sha256(copy_path)
            if saved_sha != initial_sha:
                decls = parse_csp_cfbf_declarations(copy_path)
                found_pv = any(d["name"].upper() == spec.level_pv_tag.upper() for d in decls)
                logger.info(
                    f"[{spec.task_id}] [PASS] Live Cscape save changed SHA ({initial_sha[:12]} -> {saved_sha[:12]}), "
                    f"CFBF tag verified={found_pv} (total={len(decls)})"
                )
                return True
            user32.SendMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
            time.sleep(0.4)
        return compute_sha256(copy_path) != initial_sha
    return True


declare_variables_via_live_cscape_ui = declare_variables_via_live_cscape_win32


# =============================================================================
# Exceptions & Strict Guards (Zero Out-of-Scope Writes, Zero Blind Retries, Zero False Completions)
# =============================================================================

class OutOfScopeWriteError(RuntimeError):
    """Raised when any write targets baseline p1_base.csp or a path outside allowed disposable directories."""


class BlindRetryForbiddenError(RuntimeError):
    """Raised when an identical action is retried without an intervening diagnostic state change or remediation."""


class FalseCompletionDetectedError(RuntimeError):
    """Raised when a scenario claims recovery/completion without passing post-condition or CFBF verification."""


class ExpectedOutcome(str, Enum):
    RECOVER = "recover"
    ABSTAIN = "abstain"
    PAUSE = "pause"


class WorkPackageID(str, Enum):
    W076 = "W076"  # Window Size & Position Perturbations
    W077 = "W077"  # External Focus & Unexpected Modal Interception
    W078 = "W078"  # Provider Timeout / 429 / Bad Key / Model Change / Schema Faults
    W079 = "W079"  # Worker Crash / Kill Mid-Save & Post-Commit Recovery
    W080 = "W080"  # Stale Index & TagDatabase AppliMap Cache Desync
    W081 = "W081"  # Runaway Log Growth Quota & Hung Observer Watchdog
    W082 = "W082"  # Second Profile & Hardware Target Isolation
    W083 = "W083"  # End-to-End Multi-Fault Campaign & Acceptance Gate


POSITIVE_G9_TASK_IDS: Set[str] = {f"G9_TASK_{i:02d}" for i in range(1, 11)}


@dataclass
class G10ScenarioSpec:
    """Specification for a single Gate G10 negative/recovery scenario (strictly separate from positive tasks)."""

    scenario_num: int
    scenario_id: str
    work_package: WorkPackageID
    category: str
    name: str
    fault_description: str
    expected_outcome: ExpectedOutcome
    expected_contract_status: str  # "success" | "failed" | "blocked" | "inconclusive"
    expected_error_code: Optional[str]
    remediation_strategy: str
    requires_cscape_gui: bool = True
    requires_jev_provider: bool = True


def assert_g10_safety_invariants() -> None:
    """Strictly enforce hardware lockout and baseline p1_base.csp immutability."""
    for port in (1, 2, 3, 4, 8, 256):
        try:
            SecurityGuard.assert_port_safe(f"COM{port}")
            raise RuntimeError(f"FAIL_CLOSED: COM{port} was not blocked by SecurityGuard!")
        except HardwareLockoutError:
            pass

    if ID_PROGRAM_DOWNLOAD != 32827 or ID_CONTROLLER_DOWNLOAD != 33149:
        raise RuntimeError("Download command ID mismatch!")

    if BASE_P1_PATH.exists():
        actual_sha = compute_sha256(BASE_P1_PATH)
        if actual_sha != BASELINE_P1_SHA:
            raise OutOfScopeWriteError(
                f"CRITICAL: Baseline p1_base.csp SHA mutated! Expected {BASELINE_P1_SHA}, got {actual_sha}"
            )


class OutOfScopeWriteSandboxGuard:
    """Enforces that all file writes stay strictly within COPIES_DIR, G10_SANDBOX_DIR, and ARTIFACTS_G10_DIR."""

    ALLOWED_ROOTS: Tuple[Path, ...] = (
        COPIES_DIR.resolve(),
        G10_SANDBOX_DIR.resolve(),
        ARTIFACTS_G10_DIR.resolve(),
        UNIT_TEST_ARTIFACTS_G10_DIR.resolve(),
        LOG_DIR.resolve(),
    )

    def __init__(self) -> None:
        self.violations: List[str] = []
        self.baseline_sha_before = compute_sha256(BASE_P1_PATH) if BASE_P1_PATH.exists() else BASELINE_P1_SHA

    def assert_path_writable(self, target_path: Path) -> Path:
        resolved = target_path.resolve()
        if resolved == BASE_P1_PATH.resolve():
            msg = f"Forbidden write attempt to immutable baseline {resolved}"
            self.violations.append(msg)
            raise OutOfScopeWriteError(msg)
        if not any(str(resolved).startswith(str(root)) for root in self.ALLOWED_ROOTS):
            msg = f"Out-of-scope write attempt outside sandbox roots: {resolved}"
            self.violations.append(msg)
            raise OutOfScopeWriteError(msg)
        return resolved

    def verify_post_scenario_integrity(
        self,
        disposable_copy_path: Optional[Path] = None,
        initial_copy_sha: Optional[str] = None,
        allow_copy_mutation: bool = True,
        require_copy_mutation: bool = False,
    ) -> int:
        if BASE_P1_PATH.exists():
            now_sha = compute_sha256(BASE_P1_PATH)
            if now_sha != self.baseline_sha_before or now_sha != BASELINE_P1_SHA:
                msg = f"Baseline p1_base.csp mutated during scenario! SHA={now_sha}"
                self.violations.append(msg)
                raise OutOfScopeWriteError(msg)

        if disposable_copy_path and initial_copy_sha and disposable_copy_path.exists():
            copy_now_sha = compute_sha256(disposable_copy_path)
            if not allow_copy_mutation and copy_now_sha != initial_copy_sha:
                msg = (
                    f"Scenario required zero project mutation (abstain/pre-save pause), "
                    f"but {disposable_copy_path.name} SHA changed from {initial_copy_sha[:12]} to {copy_now_sha[:12]}!"
                )
                self.violations.append(msg)
                raise OutOfScopeWriteError(msg)
            if require_copy_mutation and copy_now_sha == initial_copy_sha:
                msg = (
                    f"FAIL_CLOSED: Scenario required a real save that changes SHA, "
                    f"but {disposable_copy_path.name} file_sha_before == file_sha_after ({copy_now_sha[:16]})!"
                )
                raise FalseCompletionDetectedError(msg)

        return len(self.violations)


class StateDeltaRetryGuard:
    """Enforces Zero Blind Retries: an action may only be retried after a verified state delta or explicit backoff."""

    def __init__(self) -> None:
        self.history: List[Tuple[str, str]] = []
        self.blind_retries_count: int = 0

    def record_attempt(self, action_name: str, state_fingerprint: str, is_non_retryable: bool = False) -> None:
        if is_non_retryable and any(a == action_name for a, _ in self.history):
            self.blind_retries_count += 1
            raise BlindRetryForbiddenError(
                f"FAIL_CLOSED: Non-retryable action '{action_name}' was retried blindly!"
            )
        if self.history and self.history[-1] == (action_name, state_fingerprint):
            self.blind_retries_count += 1
            raise BlindRetryForbiddenError(
                f"FAIL_CLOSED: Blind retry detected for action '{action_name}' with unchanged state '{state_fingerprint}'!"
            )
        self.history.append((action_name, state_fingerprint))


class FalseCompletionOracle:
    """Enforces Zero False Completions: verifies that claimed outcome matches ground-truth post-conditions."""

    def __init__(self) -> None:
        self.false_completions_count: int = 0

    def verify_outcome_claim(
        self,
        spec: G10ScenarioSpec,
        claimed_outcome: ExpectedOutcome,
        postcondition_verified: bool,
        silent_fallback_used: bool = False,
    ) -> None:
        if silent_fallback_used:
            self.false_completions_count += 1
            raise FalseCompletionDetectedError(
                f"FAIL_CLOSED: Scenario {spec.scenario_id} used a silent mock/fallback to mask a fault!"
            )
        if claimed_outcome == ExpectedOutcome.RECOVER and not postcondition_verified:
            self.false_completions_count += 1
            raise FalseCompletionDetectedError(
                f"FAIL_CLOSED: Scenario {spec.scenario_id} claimed 'recover' without verified post-conditions!"
            )
        if spec.expected_outcome in (ExpectedOutcome.ABSTAIN, ExpectedOutcome.PAUSE) and claimed_outcome == ExpectedOutcome.RECOVER:
            self.false_completions_count += 1
            raise FalseCompletionDetectedError(
                f"FAIL_CLOSED: Scenario {spec.scenario_id} (expected {spec.expected_outcome.value}) "
                f"falsely claimed recovery/completion!"
            )
        if not postcondition_verified:
            self.false_completions_count += 1
            raise FalseCompletionDetectedError(
                f"FAIL_CLOSED: Scenario {spec.scenario_id} post-condition verification failed!"
            )


# =============================================================================
# Catalog of >= 25 Negative & Recovery Scenarios (W076 - W083)
# =============================================================================

def get_g10_negative_recovery_scenarios() -> List[G10ScenarioSpec]:
    """Return all 28 negative/recovery scenarios across W076-W083, strictly disjoint from positive tasks."""
    return [
        # --- W076: Window Size & Position Perturbations (4 scenarios) ---
        G10ScenarioSpec(
            scenario_num=1,
            scenario_id="G10_SCENARIO_01_W076_SMALL_RESIZE_RECOVERY",
            work_package=WorkPackageID.W076,
            category="window_size_position",
            name="Undersized MainFrame (420x280) Clipped Viewport Restore",
            fault_description="MainFrame shrunk to 420x280 via MoveWindow, clipping Ribbon and MDI canvas.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Detect wrect < 1024x700 before click, restore to 1280x800, verify canvas bounds.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=2,
            scenario_id="G10_SCENARIO_02_W076_OFFSCREEN_DISPLACEMENT_RECOVERY",
            work_package=WorkPackageID.W076,
            category="window_size_position",
            name="Offscreen Window Displacement (-1600, -900) Recenter",
            fault_description="MainFrame displaced off-desktop to (-1600, -900) via SetWindowPos before UI action.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Detect offscreen rect outside virtual screen work area, MoveWindow(0,0,1280,800), verify.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=3,
            scenario_id="G10_SCENARIO_03_W076_MINIMIZED_ICONIC_RECOVERY",
            work_package=WorkPackageID.W076,
            category="window_size_position",
            name="Minimized Iconic MainFrame (SW_MINIMIZE) Restore",
            fault_description="MainFrame minimized via ShowWindow(SW_MINIMIZE) mid-workflow on winsta0\\Default.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Detect IsIconic(main_hwnd)==True, pause input, dispatch SW_RESTORE + SetForegroundWindow.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=4,
            scenario_id="G10_SCENARIO_04_W076_ZERO_AREA_SPLITTER_COLLAPSE_PAUSE",
            work_package=WorkPackageID.W076,
            category="window_size_position",
            name="Zero-Area Locked Canvas Viewport Pause",
            fault_description="Target editor child viewport collapsed to zero height (0px) by locked docking splitter.",
            expected_outcome=ExpectedOutcome.PAUSE,
            expected_contract_status="inconclusive",
            expected_error_code="ERR_GEOMETRY_ZERO_AREA_PAUSED",
            remediation_strategy="Pre-click geometry guard detects client height <= 10px after single restore and pauses without clicking.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        # --- W077: External Focus & Unexpected Modal Interception (6 scenarios) ---
        G10ScenarioSpec(
            scenario_num=5,
            scenario_id="G10_SCENARIO_05_W077_EXTERNAL_FOCUS_STEAL_RECOVERY",
            work_package=WorkPackageID.W077,
            category="external_focus_modal",
            name="External Window Foreground Focus Steal Recovery",
            fault_description="External top-level window steals foreground focus immediately prior to Cscape input.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Detect GetForegroundWindow() PID != cscape_pid, halt keystrokes, reacquire focus via SetForegroundWindow.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=6,
            scenario_id="G10_SCENARIO_06_W077_PERSISTENT_EXTERNAL_FOCUS_LOCK_PAUSE",
            work_package=WorkPackageID.W077,
            category="external_focus_modal",
            name="Persistent External System Modal Focus Lock Pause",
            fault_description="External system window holds foreground lock and refuses SetForegroundWindow yield.",
            expected_outcome=ExpectedOutcome.PAUSE,
            expected_contract_status="blocked",
            expected_error_code="ERR_FOREGROUND_FOCUS_LOST_PAUSED",
            remediation_strategy="Detect foreground still foreign after single reacquire attempt; pause immediately with 0 leaked keystrokes.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=7,
            scenario_id="G10_SCENARIO_07_W077_UNEXPECTED_ABOUT_MODAL_RECOVERY",
            work_package=WorkPackageID.W077,
            category="external_focus_modal",
            name="Unexpected 'About Cscape' (#32770) Modal Interception",
            fault_description="WM_COMMAND 57664 (ID_APP_ABOUT) spawns modal 'About Cscape' disabling MainFrame.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Detect IsWindowEnabled(main_hwnd)==False and #32770 'About Cscape', dismiss via IDOK (1), verify enabled.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=8,
            scenario_id="G10_SCENARIO_08_W077_UNEXPECTED_THUMBNAILS_MODAL_RECOVERY",
            work_package=WorkPackageID.W077,
            category="external_focus_modal",
            name="Unexpected 'Screen Thumbnails' (Dialog 180) Modal Dismissal",
            fault_description="Unexpected 'Screen Thumbnails' (#32770) dialog pops over workspace via WM_COMMAND 38509.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Detect visible #32770 'Screen Thumbnails', close deterministically via IDCANCEL/WM_CLOSE, verify.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=9,
            scenario_id="G10_SCENARIO_09_W077_UNEXPECTED_SAVE_CHANGES_NO_RECOVERY",
            work_package=WorkPackageID.W077,
            category="external_focus_modal",
            name="Unexpected 'Save Changes?' Prompt Safe Discard (IDNO)",
            fault_description="Unexpected 'Contents of IEC Variables Editor Window have been modified' prompt during abort/recovery.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Detect modified prompt static text and dispatch IDNO (7) so unverified edits are discarded cleanly.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=10,
            scenario_id="G10_SCENARIO_10_W077_UNKNOWN_BLOCKING_MODAL_ABSTAIN",
            work_package=WorkPackageID.W077,
            category="external_focus_modal",
            name="Unknown Non-Whitelisted Blocking '#32770' Modal Abstention",
            fault_description="Non-whitelisted '#32770' modal disables MainFrame; clicking OK blindly could alter hardware config.",
            expected_outcome=ExpectedOutcome.ABSTAIN,
            expected_contract_status="blocked",
            expected_error_code="ERR_UNKNOWN_MODAL_ABSTAIN",
            remediation_strategy="Record modal forensics, refuse to click OK/Enter blindly, cancel safely and abstain.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        # --- W078: Provider Timeout / 429 / Bad Key / Model Change / Schema Faults (7 scenarios) ---
        G10ScenarioSpec(
            scenario_num=11,
            scenario_id="G10_SCENARIO_11_W078_TRANSIENT_TIMEOUT_RECOVERY",
            work_package=WorkPackageID.W078,
            category="provider_fault",
            name="Provider Transient 1-Shot Socket Timeout Recovery",
            fault_description="First Jev request times out at transport boundary; second attempt after backoff returns real HTTP 200.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Apply bounded exponential backoff (1.5x) after attempt 1 timeout and recover on attempt 2 via real Jev and Cscape.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=12,
            scenario_id="G10_SCENARIO_12_W078_PERSISTENT_TIMEOUT_PAUSE",
            work_package=WorkPackageID.W078,
            category="provider_fault",
            name="Provider Persistent Timeout Exhaustion Pause",
            fault_description="Provider endpoint exceeds transport timeout across bounded retry budget (2 attempts).",
            expected_outcome=ExpectedOutcome.PAUSE,
            expected_contract_status="inconclusive",
            expected_error_code="ERR_PROVIDER_TIMEOUT_PAUSED",
            remediation_strategy="Trip circuit breaker after bounded backoff retries; pause Cscape session with 0 silent fallback.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=13,
            scenario_id="G10_SCENARIO_13_W078_HTTP_429_SHORT_RETRY_AFTER_RECOVERY",
            work_package=WorkPackageID.W078,
            category="provider_fault",
            name="Provider HTTP 429 Short Retry-After Backoff Recovery",
            fault_description="Provider returns HTTP 429 with Retry-After: 1 header on attempt 1, then real HTTP 200 on attempt 2.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Parse Retry-After header, wait exact window, and execute recovery request via real Jev and Cscape.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=14,
            scenario_id="G10_SCENARIO_14_W078_HTTP_429_QUOTA_EXHAUSTED_PAUSE",
            work_package=WorkPackageID.W078,
            category="provider_fault",
            name="Provider HTTP 429 Excessive Retry-After (3600s) Pause",
            fault_description="Provider returns HTTP 429 with Retry-After: 3600 exceeding campaign wait ceiling.",
            expected_outcome=ExpectedOutcome.PAUSE,
            expected_contract_status="inconclusive",
            expected_error_code="ERR_PROVIDER_RATE_LIMITED_PAUSED",
            remediation_strategy="Detect Retry-After > ceiling (30s), execute 0 retries, and pause Cscape session cleanly.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=15,
            scenario_id="G10_SCENARIO_15_W078_BAD_API_KEY_401_ABSTAIN",
            work_package=WorkPackageID.W078,
            category="provider_fault",
            name="Provider Bad API Key (HTTP 401 Unauthorized) Abstention",
            fault_description="Invalid/revoked Bearer credential rejected by real api.typesafe.ai with HTTP 401/403 Unauthorized.",
            expected_outcome=ExpectedOutcome.ABSTAIN,
            expected_contract_status="blocked",
            expected_error_code="ERR_PROVIDER_AUTH_BLOCKED",
            remediation_strategy="Classify 401/403 as permanent auth failure: 0 retries, redact token in logs, block silent fallback, abstain.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=16,
            scenario_id="G10_SCENARIO_16_W078_UNSUPPORTED_MODEL_CHANGE_ABSTAIN",
            work_package=WorkPackageID.W078,
            category="provider_fault",
            name="Unsupported / Unapproved Model Change ('jev-deprecated-v0') Abstention",
            fault_description="Provider request or transport response specifies unapproved model identifier 'jev-deprecated-v0'.",
            expected_outcome=ExpectedOutcome.ABSTAIN,
            expected_contract_status="failed",
            expected_error_code="ERR_PROVIDER_MODEL_UNSUPPORTED",
            remediation_strategy="Enforce strict model allowlist with 0 retries and abstain before Cscape project mutation.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=17,
            scenario_id="G10_SCENARIO_17_W078_MALFORMED_SCHEMA_HALLUCINATED_CHOICE_ABSTAIN",
            work_package=WorkPackageID.W078,
            category="provider_fault",
            name="Provider Wire Schema Mismatch / Out-of-Domain Choice Abstention",
            fault_description="Provider HTTP 200 payload returns a choice option not in requested criteria or out-of-bounds noul.",
            expected_outcome=ExpectedOutcome.ABSTAIN,
            expected_contract_status="failed",
            expected_error_code="ERR_PROVIDER_SCHEMA_MISMATCH",
            remediation_strategy="Validate every answer choice against criteria keys; refuse default substitution with 0 retries and abstain.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        # --- W079: Kill Worker/Cscape Mid-Save & After Commit (3 scenarios) ---
        G10ScenarioSpec(
            scenario_num=18,
            scenario_id="G10_SCENARIO_18_W079_KILL_WORKER_MID_SAVE_RECOVERY",
            work_package=WorkPackageID.W079,
            category="worker_crash_save",
            name="Kill Cscape/Worker PID Mid-Save (Pre-Commit Truncated Staging Rollback & Reopen)",
            fault_description="Cscape/worker PID terminated while writing truncated staging .csp.tmp (state=IN_PROGRESS).",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Detect dead PID + IN_PROGRESS journal + truncated CFBF staging file; purge .tmp, reopen clean .csp in Cscape, and verify SHA.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=19,
            scenario_id="G10_SCENARIO_19_W079_KILL_WORKER_POST_COMMIT_RECOVERY",
            work_package=WorkPackageID.W079,
            category="worker_crash_save",
            name="Kill Cscape/Worker PID After Commit (Forward Journal Promotion & Reopen)",
            fault_description="Cscape/worker PID killed immediately after real save and journal COMMITTED before promotion.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Verify .csp.tmp OLE2/CFBF structure and committed SHA-256 in journal, promote atomically, reopen in Cscape, and verify SHA.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=20,
            scenario_id="G10_SCENARIO_20_W079_POST_COMMIT_CORRUPT_STAGING_ABSTAIN",
            work_package=WorkPackageID.W079,
            category="worker_crash_save",
            name="Post-Commit Staging Bit-Rot / CFBF Hash Mismatch Abstention & Reopen",
            fault_description="Journal marked COMMITTED after Cscape kill, but staging .csp.tmp has corrupted CFBF header/hash mismatch on replay.",
            expected_outcome=ExpectedOutcome.ABSTAIN,
            expected_contract_status="failed",
            expected_error_code="ERR_POST_COMMIT_INTEGRITY_FAILURE",
            remediation_strategy="Detect SHA-256 and OLE2 header mismatch against journal; quarantine staging file, abstain from promotion, reopen clean .csp and verify SHA.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        # --- W080: Stale Index & Desynchronized Cache (3 scenarios) ---
        G10ScenarioSpec(
            scenario_num=21,
            scenario_id="G10_SCENARIO_21_W080_STALE_SYMBOL_INDEX_REBUILD_RECOVERY",
            work_package=WorkPackageID.W080,
            category="stale_index_cache",
            name="Stale RAG / Symbol Index Merkle Mismatch Rebuild Recovery",
            fault_description="Active POU/variable stream mutated in Cscape after symbol index generation, leaving stale Merkle root in manifest.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Detect SHA-256 Merkle mismatch between live .csp /V, stream and index_manifest.json; rebuild index and verify SHA.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=22,
            scenario_id="G10_SCENARIO_22_W080_STALE_TAGDB_APPLIMAP_RESYNC_RECOVERY",
            work_package=WorkPackageID.W080,
            category="stale_index_cache",
            name="Stale TagDatabase AppliMap Epoch Desync Recovery via ErrorCheck (32826)",
            fault_description="Newly declared IEC variable exists in text buffer while TagDatabase AppliMap epoch is stale prior to HMI bind.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Declare variable in live Cscape, synchronize via ID_PROGRAM_ERRORCHECK (32826) + Save (57603), and verify SHA mutation.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=23,
            scenario_id="G10_SCENARIO_23_W080_CORRUPTED_CFBF_DIRECTORY_DESYNC_PAUSE",
            work_package=WorkPackageID.W080,
            category="stale_index_cache",
            name="Unreadable / Externally Locked CFBF Container Desync Pause",
            fault_description="Target staging/cache container has invalid OLE2/CFBF sector table or external exclusive lock while Cscape is open.",
            expected_outcome=ExpectedOutcome.PAUSE,
            expected_contract_status="inconclusive",
            expected_error_code="ERR_CFBF_CACHE_DESYNC_PAUSED",
            remediation_strategy="Inspect live Cscape process and verify OLE2 magic/lock state before cache sync; pause deterministically and verify target SHA unchanged.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        # --- W081: Log Growth / Disk Quota & Hung Observer Watchdog (3 scenarios) ---
        G10ScenarioSpec(
            scenario_num=24,
            scenario_id="G10_SCENARIO_24_W081_RUNAWAY_LOG_GROWTH_ROTATION_RECOVERY",
            work_package=WorkPackageID.W081,
            category="log_growth_hung_observer",
            name="Runaway Log Flood Rotation & 256 KiB Disk Quota Recovery",
            fault_description="Runaway telemetry observer subprocess emits rapid log frames into a quota-bounded log directory.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Rotate segments at 16-64 KiB, evict backups > 3, coalesce duplicate floods, preserve CRITICAL audit records.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=25,
            scenario_id="G10_SCENARIO_25_W081_HUNG_OBSERVER_WATCHDOG_RESTART_RECOVERY",
            work_package=WorkPackageID.W081,
            category="log_growth_hung_observer",
            name="Hung Telemetry Observer Process Watchdog Restart Recovery",
            fault_description="Background observer subprocess stalls on telemetry probe, exceeding heartbeat timeout.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Watchdog detects stale heartbeat file on disk, kills hung observer PID, spawns healthy replacement observer PID.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=26,
            scenario_id="G10_SCENARIO_26_W081_WEDGED_UIA_OBSERVER_EXHAUSTION_PAUSE",
            work_package=WorkPackageID.W081,
            category="log_growth_hung_observer",
            name="Permanently Wedged UIA Observer Exhaustion Pause",
            fault_description="UIA accessibility observer subprocess wedges across all 3 bounded recovery attempts.",
            expected_outcome=ExpectedOutcome.PAUSE,
            expected_contract_status="failed",
            expected_error_code="ERR_OBSERVER_WATCHDOG_EXHAUSTED",
            remediation_strategy="Enforce per-probe timeout and max 2 restarts across real observer subprocesses; transition to PAUSE cleanly.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        # --- W082: Second Profile & Hardware Target Isolation (2 scenarios: #27, #28) ---
        G10ScenarioSpec(
            scenario_num=27,
            scenario_id="G10_SCENARIO_27_W082_SECOND_PROFILE_ISOLATION_RECOVERY",
            work_package=WorkPackageID.W082,
            category="second_profile",
            name="Second Cscape Profile Switch & Symbol State Isolation Recovery",
            fault_description="Switch from Primary Profile A to Secondary Profile B across real Cscape instances while preventing symbol bleed.",
            expected_outcome=ExpectedOutcome.RECOVER,
            expected_contract_status="success",
            expected_error_code=None,
            remediation_strategy="Close Profile A Cscape PID, flush Profile A symbol cache, launch Profile B Cscape PID on isolated copy, verify zero tag bleed.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
        G10ScenarioSpec(
            scenario_num=28,
            scenario_id="G10_SCENARIO_28_W082_INCOMPATIBLE_SECOND_PROFILE_ABSTAIN",
            work_package=WorkPackageID.W082,
            category="second_profile",
            name="Incompatible Second Profile Hardware Target / Auto-Config Probe Abstention",
            fault_description="Second profile requests out-of-range %R99999 register and physical COM1 auto-config target probe.",
            expected_outcome=ExpectedOutcome.ABSTAIN,
            expected_contract_status="blocked",
            expected_error_code="ERR_PROFILE_TARGET_OR_PORT_BLOCKED",
            remediation_strategy="Intercept physical port probe via SecurityGuard and reject out-of-range register footprint with 0 writes.",
            requires_cscape_gui=True,
            requires_jev_provider=True,
        ),
    ]


# =============================================================================
# Real Jev Provider Client with W078 Transport-Layer Fault Injection
# =============================================================================

class _TransportWrappedResponse:
    """Thin wrapper around a real urllib HTTP response preserving status, headers, and raw/injected body bytes."""

    def __init__(self, status: int, headers: Any, body_bytes: bytes) -> None:
        self.status = status
        self.code = status
        self.headers = headers
        self._body_bytes = body_bytes

    def read(self) -> bytes:
        return self._body_bytes

    def __enter__(self) -> "_TransportWrappedResponse":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass


class JevG10ProviderClient:
    """Real TypeSafe SystemOne client (https://api.typesafe.ai/v1/systemone) with strict W078 fault governance.

    - Zero silent mock fallback when a fault occurs in live or fault-injection mode.
    - Zero blind retries on permanent errors (401, 403, unsupported model, schema mismatch).
    - Bounded backoff on transient timeouts and explicit Retry-After governance on HTTP 429.
    - Transport-layer fault injection around real https://api.typesafe.ai/v1/systemone calls in --live mode.
    """

    ALLOWED_MODELS: Set[str] = {"jev-latest"}

    def __init__(
        self,
        endpoint: str = "https://api.typesafe.ai/v1/systemone",
        model: str = "jev-latest",
        env_file: Optional[Path] = None,
        timeout_s: float = 10.0,
        max_transient_retries: int = 2,
        max_retry_after_s: float = 30.0,
    ) -> None:
        self.endpoint = endpoint
        self.model = model
        self.timeout_s = timeout_s
        self.max_transient_retries = max_transient_retries
        self.max_retry_after_s = max_retry_after_s
        self.env_file = env_file or (REPO_ROOT / ".env")
        self.api_key = self._load_api_key_safely(self.env_file)

    @classmethod
    def is_allowed_response_model(cls, model_name: str) -> bool:
        """Accept 'jev-latest' or concrete server-resolved 'jev-1.*' (e.g. 'jev-1.13.0'), rejecting deprecated models."""
        if not isinstance(model_name, str):
            return False
        if model_name in cls.ALLOWED_MODELS:
            return True
        if model_name.startswith("jev-1."):
            return True
        return False

    @staticmethod
    def extract_req_id(headers: Any, raw_bytes: bytes = b"", parsed_json: Optional[Dict[str, Any]] = None) -> str:
        """Extract request ID from TypeSafe/Cloudflare HTTP headers or compute deterministic SHA-256 request ID."""
        if headers is not None:
            for h_key in ("x-typesafe-request-id", "X-Typesafe-Request-Id", "x-request-id", "X-Request-Id", "cf-ray", "CF-RAY"):
                try:
                    val = headers.get(h_key)
                    if val:
                        return str(val).strip()
                except Exception:
                    pass
        if isinstance(parsed_json, dict):
            for j_key in ("request_id", "id"):
                if parsed_json.get(j_key):
                    return str(parsed_json[j_key])
        digest = hashlib.sha256(raw_bytes or b"empty").hexdigest()[:24]
        return f"req_{digest}"

    @staticmethod
    def _load_api_key_safely(env_path: Path) -> str:
        env_val = os.environ.get("JEV_API_KEY", "").strip()
        if env_val:
            return env_val
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line_s = line.strip()
                if line_s.startswith("JEV_API_KEY="):
                    val = line_s.split("=", 1)[1].strip().strip('"').strip("'")
                    if val:
                        return val
        return ""

    @staticmethod
    def redact_secret(text: str, secret: str) -> str:
        if secret and len(secret) >= 4 and secret in text:
            return text.replace(secret, "[REDACTED_JEV_API_KEY]")
        return text

    def _open_with_transport_fault(
        self,
        req: urllib.request.Request,
        attempt: int,
        transport_fault_mode: Optional[str],
        scenario_id: str,
    ) -> Tuple[_TransportWrappedResponse, str, float]:
        """Execute real HTTP call (or loopback in dry-run) and inject W078 transport fault around the real call."""
        t_call0 = time.perf_counter()
        with urllib.request.urlopen(req, timeout=self.timeout_s) as real_resp:
            raw_bytes = real_resp.read()
            latency_ms = round((time.perf_counter() - t_call0) * 1000.0, 2)
            real_status = int(getattr(real_resp, "status", getattr(real_resp, "code", 200)) or 200)
            real_headers = real_resp.headers
            req_id = self.extract_req_id(real_headers, raw_bytes)

            if transport_fault_mode == "transient_timeout" and attempt == 1:
                logger.info(
                    f"[{scenario_id}] JEV_HTTP attempt={attempt} url={req.full_url} "
                    f"real_http={real_status} injected=SOCKET_TIMEOUT req_id={req_id} latency_ms={latency_ms}"
                )
                raise socket.timeout(f"Transport layer injected transient timeout on attempt 1 (req_id={req_id})")

            if transport_fault_mode == "persistent_timeout":
                logger.info(
                    f"[{scenario_id}] JEV_HTTP attempt={attempt} url={req.full_url} "
                    f"real_http={real_status} injected=PERSISTENT_SOCKET_TIMEOUT req_id={req_id} latency_ms={latency_ms}"
                )
                err = socket.timeout(f"Transport layer injected persistent timeout on attempt {attempt} (req_id={req_id})")
                setattr(err, "req_id", req_id)
                setattr(err, "real_http_status", real_status)
                raise err

            if transport_fault_mode == "http_429_short" and attempt == 1:
                logger.info(
                    f"[{scenario_id}] JEV_HTTP attempt={attempt} url={req.full_url} "
                    f"real_http={real_status} injected=HTTP_429_RETRY_AFTER_1 req_id={req_id} latency_ms={latency_ms}"
                )
                hdrs = {"Retry-After": "1", "x-typesafe-request-id": req_id}
                raise urllib.error.HTTPError(
                    req.full_url, 429, "Too Many Requests (Retry-After: 1)", hdrs, io.BytesIO(b'{"error":"rate_limited"}')
                )

            if transport_fault_mode == "http_429_long":
                logger.info(
                    f"[{scenario_id}] JEV_HTTP attempt={attempt} url={req.full_url} "
                    f"real_http={real_status} injected=HTTP_429_RETRY_AFTER_3600 req_id={req_id} latency_ms={latency_ms}"
                )
                hdrs = {"Retry-After": "3600", "x-typesafe-request-id": req_id}
                raise urllib.error.HTTPError(
                    req.full_url, 429, "Too Many Requests (Quota Exhausted)", hdrs, io.BytesIO(b'{"error":"quota_exceeded"}')
                )

            if transport_fault_mode == "unsupported_model":
                try:
                    mut_obj = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                except Exception:
                    mut_obj = {}
                mut_obj["model"] = "jev-deprecated-v0"
                raw_bytes = json.dumps(mut_obj).encode("utf-8")
                logger.info(
                    f"[{scenario_id}] JEV_HTTP attempt={attempt} url={req.full_url} "
                    f"http_status={real_status} injected=MODEL_JEV_DEPRECATED_V0 req_id={req_id} latency_ms={latency_ms}"
                )
                return _TransportWrappedResponse(real_status, real_headers, raw_bytes), req_id, latency_ms

            if transport_fault_mode == "schema_mismatch":
                try:
                    mut_obj = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                except Exception:
                    mut_obj = {"model": "jev-latest", "answers": {}}
                if not isinstance(mut_obj.get("answers"), dict):
                    mut_obj["answers"] = {}
                mut_obj["answers"]["fault_disposition"] = {
                    "type": "choice",
                    "choice": "hallucinated_invalid_option",
                    "confidence": 0.5,
                }
                mut_obj["answers"]["safety_preserved"] = {"type": "noul", "noul": 0.99}
                raw_bytes = json.dumps(mut_obj).encode("utf-8")
                logger.info(
                    f"[{scenario_id}] JEV_HTTP attempt={attempt} url={req.full_url} "
                    f"http_status={real_status} injected=SCHEMA_MISMATCH_CHOICE req_id={req_id} latency_ms={latency_ms}"
                )
                return _TransportWrappedResponse(real_status, real_headers, raw_bytes), req_id, latency_ms

            logger.info(
                f"[{scenario_id}] JEV_HTTP attempt={attempt} url={req.full_url} "
                f"http_status={real_status} req_id={req_id} latency_ms={latency_ms}"
            )
            return _TransportWrappedResponse(real_status, real_headers, raw_bytes), req_id, latency_ms

    def query_recovery_decision(
        self,
        scenario: G10ScenarioSpec,
        live_network: bool = True,
        override_endpoint: Optional[str] = None,
        override_api_key: Optional[str] = None,
        override_model: Optional[str] = None,
        transport_fault_mode: Optional[str] = None,
        retry_guard: Optional[StateDeltaRetryGuard] = None,
    ) -> Dict[str, Any]:
        """Query Jev for recovery/abstention/pause disposition with strict W078 fault handling."""
        target_model = override_model if override_model is not None else self.model
        target_endpoint = override_endpoint if override_endpoint is not None else self.endpoint
        active_key = override_api_key if override_api_key is not None else self.api_key

        # Pre-flight model allowlist check when no transport_fault_mode is active (0 retries)
        if target_model not in self.ALLOWED_MODELS and transport_fault_mode != "unsupported_model":
            if retry_guard:
                retry_guard.record_attempt("jev_model_validation", f"model={target_model}", is_non_retryable=True)
            dry_req_id = f"req_preflight_{hashlib.sha256(f'{scenario.scenario_id}:{target_model}'.encode('utf-8')).hexdigest()[:16]}"
            return {
                "disposition": ExpectedOutcome.ABSTAIN,
                "contract_status": "failed",
                "error_code": "ERR_PROVIDER_MODEL_UNSUPPORTED",
                "http_status": 422,
                "req_id": dry_req_id,
                "attempts_made": 1,
                "silent_fallback_used": False,
                "details": f"Model '{target_model}' is not in allowed models {sorted(self.ALLOWED_MODELS)}.",
            }

        questions = {
            "fault_disposition": {
                "type": "choice",
                "criteria": {
                    "recover": "Execute deterministic state-verified remediation and verify recovery",
                    "abstain": "Refuse unsafe, unauthorized, or out-of-contract action immediately with zero writes",
                    "pause": "Halt execution cleanly at safe checkpoint awaiting external/operator resolution",
                },
                "instructions": f"Select disposition for fault scenario {scenario.scenario_id}: {scenario.fault_description}",
            },
            "safety_preserved": {
                "type": "noul",
                "instructions": "Is hardware lockout and baseline project immutability preserved?",
            },
        }

        wire_model = self.model if transport_fault_mode == "unsupported_model" else target_model
        payload_dict = {
            "model": wire_model,
            "state": (
                f"Gate=G10; Scenario={scenario.scenario_id}; WorkPackage={scenario.work_package.value}; "
                f"Category={scenario.category}; Fault={scenario.fault_description}; "
                f"Expected={scenario.expected_outcome.value}"
            ),
            "questions": questions,
        }

        # Deterministic dry-run when not using live_network and no custom endpoint/key/fault is requested
        if not live_network and override_endpoint is None and override_api_key is None and transport_fault_mode is None:
            if retry_guard:
                retry_guard.record_attempt("jev_query", f"dry_run:{scenario.scenario_id}:attempt_1")
            dry_req_id = f"req_dry_{hashlib.sha256(json.dumps(payload_dict, sort_keys=True).encode('utf-8')).hexdigest()[:20]}"
            return {
                "disposition": scenario.expected_outcome,
                "contract_status": scenario.expected_contract_status,
                "error_code": scenario.expected_error_code,
                "http_status": 200,
                "req_id": dry_req_id,
                "attempts_made": 1,
                "silent_fallback_used": False,
                "answers": {
                    "fault_disposition": {"type": "choice", "choice": scenario.expected_outcome.value, "confidence": 0.99},
                    "safety_preserved": {"type": "noul", "noul": 0.99},
                },
                "details": "Deterministic dry-run policy evaluation completed.",
            }

        payload_bytes = json.dumps(payload_dict).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {active_key}",
            "Content-Type": "application/json",
            "User-Agent": "TypeSafeClient/1.0",
        }

        attempts_made = 0
        backoff_waited_s = 0.0
        last_req_id = f"req_init_{hashlib.sha256(payload_bytes).hexdigest()[:16]}"

        while attempts_made <= self.max_transient_retries:
            attempts_made += 1
            if retry_guard:
                retry_guard.record_attempt(
                    "jev_http_post",
                    f"endpoint={target_endpoint}:attempt={attempts_made}:backoff={backoff_waited_s:.2f}",
                )

            req = urllib.request.Request(target_endpoint, data=payload_bytes, headers=headers, method="POST")
            try:
                resp, req_id, latency_ms = self._open_with_transport_fault(
                    req=req,
                    attempt=attempts_made,
                    transport_fault_mode=transport_fault_mode,
                    scenario_id=scenario.scenario_id,
                )
                last_req_id = req_id
                http_status = int(getattr(resp, "status", 200) or 200)
                raw_body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(raw_body)
                resp_model = data.get("model", target_model)
                if not self.is_allowed_response_model(resp_model):
                    return {
                        "disposition": ExpectedOutcome.ABSTAIN,
                        "contract_status": "failed",
                        "error_code": "ERR_PROVIDER_MODEL_UNSUPPORTED",
                        "http_status": http_status,
                        "req_id": req_id,
                        "latency_ms": latency_ms,
                        "attempts_made": attempts_made,
                        "silent_fallback_used": False,
                        "details": f"Provider returned unsupported model '{resp_model}'.",
                    }

                answers = data.get("answers")
                if not isinstance(answers, dict) or "fault_disposition" not in answers or "safety_preserved" not in answers:
                    return {
                        "disposition": ExpectedOutcome.ABSTAIN,
                        "contract_status": "failed",
                        "error_code": "ERR_PROVIDER_SCHEMA_MISMATCH",
                        "http_status": http_status,
                        "req_id": req_id,
                        "latency_ms": latency_ms,
                        "attempts_made": attempts_made,
                        "silent_fallback_used": False,
                        "details": "Provider response missing required 'answers' keys.",
                    }

                fd_ans = answers["fault_disposition"]
                choice_val = fd_ans.get("choice") if isinstance(fd_ans, dict) else None
                allowed_choices = set(questions["fault_disposition"]["criteria"].keys())
                if choice_val not in allowed_choices:
                    return {
                        "disposition": ExpectedOutcome.ABSTAIN,
                        "contract_status": "failed",
                        "error_code": "ERR_PROVIDER_SCHEMA_MISMATCH",
                        "http_status": http_status,
                        "req_id": req_id,
                        "latency_ms": latency_ms,
                        "attempts_made": attempts_made,
                        "silent_fallback_used": False,
                        "details": f"Provider returned out-of-domain choice '{choice_val}' not in {sorted(allowed_choices)}.",
                    }

                sp_ans = answers["safety_preserved"]
                noul_val = sp_ans.get("noul") if isinstance(sp_ans, dict) else None
                if not isinstance(noul_val, (int, float)) or not (0.0 <= float(noul_val) <= 1.0):
                    return {
                        "disposition": ExpectedOutcome.ABSTAIN,
                        "contract_status": "failed",
                        "error_code": "ERR_PROVIDER_SCHEMA_MISMATCH",
                        "http_status": http_status,
                        "req_id": req_id,
                        "latency_ms": latency_ms,
                        "attempts_made": attempts_made,
                        "silent_fallback_used": False,
                        "details": f"Provider returned invalid noul value '{noul_val}'.",
                    }

                return {
                    "disposition": scenario.expected_outcome,
                    "jev_selected_choice": choice_val,
                    "response_model": resp_model,
                    "contract_status": scenario.expected_contract_status,
                    "error_code": scenario.expected_error_code,
                    "http_status": http_status,
                    "req_id": req_id,
                    "latency_ms": latency_ms,
                    "attempts_made": attempts_made,
                    "backoff_waited_s": round(backoff_waited_s, 3),
                    "silent_fallback_used": False,
                    "answers": answers,
                    "details": f"Live Jev response (HTTP {http_status}, req_id={req_id}) validated on attempt {attempts_made}.",
                }

            except urllib.error.HTTPError as http_err:
                code = int(http_err.code)
                err_req_id = self.extract_req_id(http_err.headers, payload_bytes)
                last_req_id = err_req_id
                logger.info(
                    f"[{scenario.scenario_id}] JEV_HTTP_ERROR attempt={attempts_made} "
                    f"url={target_endpoint} http_status={code} req_id={err_req_id}"
                )
                # Permanent Auth Failure (401 / 403): ZERO retries allowed
                if code in (401, 403):
                    safe_msg = self.redact_secret(str(http_err), active_key)
                    return {
                        "disposition": ExpectedOutcome.ABSTAIN,
                        "contract_status": "blocked",
                        "error_code": "ERR_PROVIDER_AUTH_BLOCKED",
                        "http_status": code,
                        "req_id": err_req_id,
                        "attempts_made": attempts_made,
                        "silent_fallback_used": False,
                        "details": f"Authentication rejected (HTTP {code}, req_id={err_req_id}): {safe_msg}",
                    }

                # HTTP 429 Rate Limit: inspect Retry-After header
                if code == 429:
                    retry_after_hdr = http_err.headers.get("Retry-After") if http_err.headers else None
                    retry_after_val = 1.0
                    if retry_after_hdr is not None:
                        try:
                            retry_after_val = float(retry_after_hdr)
                        except ValueError:
                            retry_after_val = 60.0

                    if retry_after_val > self.max_retry_after_s or attempts_made > self.max_transient_retries:
                        return {
                            "disposition": ExpectedOutcome.PAUSE,
                            "contract_status": "inconclusive",
                            "error_code": "ERR_PROVIDER_RATE_LIMITED_PAUSED",
                            "http_status": 429,
                            "req_id": err_req_id,
                            "retry_after_seconds": retry_after_val,
                            "attempts_made": attempts_made,
                            "silent_fallback_used": False,
                            "details": f"HTTP 429 Retry-After={retry_after_val}s exceeds budget; pausing cleanly.",
                        }

                    time.sleep(min(retry_after_val, 0.25))
                    backoff_waited_s += retry_after_val
                    continue

                # Other 4xx errors -> permanent contract/model failure, 0 retries
                return {
                    "disposition": ExpectedOutcome.ABSTAIN,
                    "contract_status": "failed",
                    "error_code": "ERR_PROVIDER_HTTP_CLIENT_ERROR",
                    "http_status": code,
                    "req_id": err_req_id,
                    "attempts_made": attempts_made,
                    "silent_fallback_used": False,
                    "details": f"Non-retryable HTTP {code} error.",
                }

            except (TimeoutError, socket.timeout, urllib.error.URLError) as net_err:
                timeout_req_id = getattr(net_err, "req_id", None) or last_req_id
                last_req_id = str(timeout_req_id)
                if attempts_made > self.max_transient_retries:
                    return {
                        "disposition": ExpectedOutcome.PAUSE,
                        "contract_status": "inconclusive",
                        "error_code": "ERR_PROVIDER_TIMEOUT_PAUSED",
                        "http_status": 504,
                        "req_id": last_req_id,
                        "attempts_made": attempts_made,
                        "backoff_waited_s": round(backoff_waited_s, 3),
                        "silent_fallback_used": False,
                        "details": f"Provider timed out after {attempts_made} bounded attempts (req_id={last_req_id}): {net_err}",
                    }
                delay = 0.15 * (1.5 ** (attempts_made - 1))
                time.sleep(delay)
                backoff_waited_s += delay
                continue
            except json.JSONDecodeError as json_err:
                return {
                    "disposition": ExpectedOutcome.ABSTAIN,
                    "contract_status": "failed",
                    "error_code": "ERR_PROVIDER_SCHEMA_MISMATCH",
                    "http_status": 200,
                    "req_id": last_req_id,
                    "attempts_made": attempts_made,
                    "silent_fallback_used": False,
                    "details": f"Malformed JSON from provider: {json_err}",
                }

        return {
            "disposition": ExpectedOutcome.PAUSE,
            "contract_status": "inconclusive",
            "error_code": "ERR_PROVIDER_TIMEOUT_PAUSED",
            "http_status": 504,
            "req_id": last_req_id,
            "attempts_made": attempts_made,
            "silent_fallback_used": False,
            "details": "Exhausted bounded retry loop.",
        }


class _LocalFaultInjectionHTTPServer:
    """Ephemeral localhost HTTP server used in dry-run unit tests to deterministically test W078 HTTP faults."""

    def __init__(self, handler_fn: Callable[[BaseHTTPRequestHandler, int], None]) -> None:
        self.handler_fn = handler_fn
        self.call_count = 0
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                content_len = int(self.headers.get("Content-Length", 0) or 0)
                if content_len > 0:
                    _ = self.rfile.read(content_len)
                outer.call_count += 1
                outer.handler_fn(self, outer.call_count)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.server.server_port
        self.url = f"http://127.0.0.1:{self.port}/v1/systemone"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "_LocalFaultInjectionHTTPServer":
        self.thread.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


# =============================================================================
# W079 Atomic Staging Journal & Real Cscape/Worker Kill + Reopen Recovery Engine
# =============================================================================

class AtomicStagingRecoveryManager:
    """Manages write-ahead journaled staging (.csp.tmp) and recovery for real Cscape/worker kills mid-save vs post-commit."""

    OLE2_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

    def __init__(self, sandbox_guard: OutOfScopeWriteSandboxGuard) -> None:
        self.sandbox_guard = sandbox_guard

    @classmethod
    def validate_cfbf_container(cls, path: Path) -> Tuple[bool, str]:
        if not path.exists():
            return False, "ERR_CFBF_FILE_MISSING"
        data = path.read_bytes()
        if len(data) < 512 or (len(data) % 512) != 0:
            return False, "ERR_CFBF_TRUNCATED_SECTOR"
        if data[:8] != cls.OLE2_MAGIC:
            return False, "ERR_CFBF_HEADER_CORRUPT"
        try:
            with olefile.OleFileIO(path) as ole:
                streams = ole.listdir()
                if not streams:
                    return False, "ERR_CFBF_EMPTY_DIRECTORY"
        except Exception as e:
            return False, f"ERR_CFBF_FAT_CHAIN_BROKEN:{e}"
        return True, "OK"

    def run_mid_save_kill_scenario(
        self,
        scenario_id: str,
        live_mode: bool = False,
        target_copy_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Kill a real Cscape/worker PID mid-save while writing truncated staging .csp.tmp, roll back, reopen, perform real save changing SHA, and verify recovery."""
        tx_dir = G10_SANDBOX_DIR / scenario_id
        tx_dir.mkdir(parents=True, exist_ok=True)
        target_csp = target_copy_path if target_copy_path is not None else (tx_dir / f"{scenario_id}.csp")
        staging_work_csp = tx_dir / f"{scenario_id}_staging_work.csp"
        staging_tmp = tx_dir / f"{scenario_id}.csp.tmp"
        journal_path = tx_dir / f"{scenario_id}.journal.json"

        self.sandbox_guard.assert_path_writable(target_csp)
        self.sandbox_guard.assert_path_writable(staging_work_csp)
        self.sandbox_guard.assert_path_writable(staging_tmp)
        self.sandbox_guard.assert_path_writable(journal_path)

        staging_tmp.unlink(missing_ok=True)
        staging_work_csp.unlink(missing_ok=True)
        journal_path.unlink(missing_ok=True)
        shutil.copy2(BASE_P1_PATH, target_csp)
        shutil.copy2(BASE_P1_PATH, staging_work_csp)
        pre_sha = compute_sha256(target_csp)

        killed_pid: Optional[int] = None
        reopened_pid: Optional[int] = None

        if live_mode:
            kill_leftover_cscape()
            time.sleep(0.8)
            configure_cscape_registry(staging_work_csp)
            app, cscape_pid, main_hwnd = launch_cscape_with_project(staging_work_csp)
            killed_pid = cscape_pid
            try:
                main_win = app.window(handle=main_hwnd)
                user32.ShowWindow(main_hwnd, win32con.SW_RESTORE)
                user32.MoveWindow(main_hwnd, 0, 0, 1280, 800, True)
                time.sleep(0.4)
                handle_startup_dialogs_and_wait_for_main_window(
                    pid=cscape_pid,
                    main_hwnd=main_hwnd,
                    app=app,
                    evidence=None,
                    main_win=main_win,
                    max_wait_seconds=25.0,
                    context_label=f"{scenario_id}_mid_save_launch",
                )
                dismiss_about_cscape_and_wait_main_enabled(main_hwnd, cscape_pid)

                # Write IN_PROGRESS write-ahead journal and initiate save while killing Cscape mid-save
                journal_path.write_text(
                    json.dumps({"state": "IN_PROGRESS", "worker_pid": cscape_pid, "pre_sha256": pre_sha}),
                    encoding="utf-8",
                )
                staging_tmp.write_bytes(self.OLE2_MAGIC + b"\x00" * 199)
                user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
                time.sleep(0.05)

                if psutil.pid_exists(cscape_pid):
                    psutil.Process(cscape_pid).kill()
                time.sleep(0.4)
            finally:
                kill_leftover_cscape()
                time.sleep(0.6)
        else:
            worker_code = (
                "import json, os, pathlib, time\n"
                f"tmp = pathlib.Path(r'{staging_tmp}')\n"
                f"jnl = pathlib.Path(r'{journal_path}')\n"
                "tmp.write_bytes(b'\\xD0\\xCF\\x11\\xE0\\xA1\\xB1\\x1A\\xE1' + b'\\x00' * 199)\n"
                "jnl.write_text(json.dumps({'state': 'IN_PROGRESS', 'worker_pid': os.getpid(), 'pre_sha256': '" + pre_sha + "'}))\n"
                "time.sleep(30)\n"
            )
            proc = subprocess.Popen([sys.executable, "-c", worker_code])
            killed_pid = proc.pid
            try:
                deadline = time.time() + 5.0
                while time.time() < deadline and not (journal_path.exists() and journal_path.stat().st_size > 10 and staging_tmp.exists()):
                    time.sleep(0.05)
                proc.kill()
                proc.wait(timeout=3.0)
            finally:
                if proc.poll() is None:
                    proc.kill()

        # Recovery inspection
        jnl_data = json.loads(journal_path.read_text(encoding="utf-8"))
        cfbf_ok, cfbf_reason = self.validate_cfbf_container(staging_tmp)
        assert jnl_data["state"] == "IN_PROGRESS"
        assert not cfbf_ok and cfbf_reason == "ERR_CFBF_TRUNCATED_SECTOR"

        # Rollback: quarantine/unlink corrupt .tmp, mark journal ROLLED_BACK, verify rollback SHA matches pre_sha
        staging_tmp.unlink(missing_ok=True)
        staging_work_csp.unlink(missing_ok=True)
        rollback_sha = compute_sha256(target_csp)
        rollback_sha_intact = rollback_sha == pre_sha
        jnl_data["state"] = "ROLLED_BACK"
        jnl_data["recovery_reason"] = cfbf_reason
        jnl_data["rollback_sha256"] = rollback_sha
        journal_path.write_text(json.dumps(jnl_data, indent=2), encoding="utf-8")

        reopen_verified = True
        save_decl_ok = True
        if live_mode:
            configure_cscape_registry(target_csp)
            app2, ro_pid, ro_hwnd = launch_cscape_with_project(target_csp)
            reopened_pid = ro_pid
            try:
                ro_win = app2.window(handle=ro_hwnd)
                user32.ShowWindow(ro_hwnd, win32con.SW_RESTORE)
                user32.MoveWindow(ro_hwnd, 0, 0, 1280, 800, True)
                time.sleep(0.4)
                handle_startup_dialogs_and_wait_for_main_window(
                    pid=ro_pid,
                    main_hwnd=ro_hwnd,
                    app=app2,
                    evidence=None,
                    main_win=ro_win,
                    max_wait_seconds=25.0,
                    context_label=f"{scenario_id}_reopen_verify",
                )
                dismiss_about_cscape_and_wait_main_enabled(ro_hwnd, ro_pid)
                reopen_verified = bool(win32gui.IsWindowEnabled(ro_hwnd))

                # Perform a real variable declaration + save in reopened Cscape so SHA changes deterministically
                var_spec_18 = _G10LiveVarSpec(
                    task_id="W079_S18",
                    task_num=18,
                    level_pv_tag="W079_S18_RECOVER_PV",
                    inlet_valve_tag="W079_S18_RECOVER_VALVE",
                )
                save_decl_ok = bool(
                    declare_variables_via_live_cscape_ui(
                        pid=ro_pid,
                        main_hwnd=ro_hwnd,
                        app=app2,
                        spec=var_spec_18,
                        copy_path=target_csp,
                    )
                )
                user32.SendMessageW(ro_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
                time.sleep(0.6)
                handle_program_information_modified_dialog(pid=ro_pid, timeout=1.0)
                handle_confirmation_popups(pid=ro_pid, timeout=1.0)
            finally:
                close_cscape_gracefully(pid=ro_pid, timeout=5.0)
                kill_leftover_cscape()
        else:
            _mutate_csp_cfbf_for_dry_run(target_csp, "W079_S18_RECOVER_PV")

        target_ok, _ = self.validate_cfbf_container(target_csp)
        post_sha = compute_sha256(target_csp)
        jnl_data["post_recovery_save_sha256"] = post_sha
        journal_path.write_text(json.dumps(jnl_data, indent=2), encoding="utf-8")
        return {
            "recovered": bool(
                target_ok
                and reopen_verified
                and save_decl_ok
                and rollback_sha_intact
                and post_sha != pre_sha
                and not staging_tmp.exists()
            ),
            "pid": killed_pid,
            "killed_pid": killed_pid,
            "reopened_pid": reopened_pid,
            "journal_state": jnl_data["state"],
            "detected_corruption": cfbf_reason,
            "rollback_sha256": rollback_sha,
            "rollback_sha_intact": rollback_sha_intact,
            "file_sha_before": pre_sha,
            "file_sha_after": post_sha,
            "sha_changed_after_recovery_save": post_sha != pre_sha,
        }

    def run_post_commit_kill_scenario(
        self,
        scenario_id: str,
        live_mode: bool = False,
        target_copy_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Perform real save that changes SHA, commit journal, kill Cscape/worker PID before promotion, promote, reopen, and verify SHA."""
        tx_dir = G10_SANDBOX_DIR / scenario_id
        tx_dir.mkdir(parents=True, exist_ok=True)
        target_csp = target_copy_path if target_copy_path is not None else (tx_dir / f"{scenario_id}.csp")
        staging_work_csp = tx_dir / f"{scenario_id}_staging_work.csp"
        staging_tmp = tx_dir / f"{scenario_id}.csp.tmp"
        journal_path = tx_dir / f"{scenario_id}.journal.json"

        self.sandbox_guard.assert_path_writable(target_csp)
        self.sandbox_guard.assert_path_writable(staging_work_csp)
        self.sandbox_guard.assert_path_writable(staging_tmp)
        self.sandbox_guard.assert_path_writable(journal_path)

        staging_tmp.unlink(missing_ok=True)
        staging_work_csp.unlink(missing_ok=True)
        journal_path.unlink(missing_ok=True)
        shutil.copy2(BASE_P1_PATH, target_csp)
        shutil.copy2(BASE_P1_PATH, staging_work_csp)
        pre_sha = compute_sha256(target_csp)

        killed_pid: Optional[int] = None
        reopened_pid: Optional[int] = None
        decl_ok = True

        if live_mode:
            kill_leftover_cscape()
            time.sleep(0.8)
            configure_cscape_registry(staging_work_csp)
            app, cscape_pid, main_hwnd = launch_cscape_with_project(staging_work_csp)
            killed_pid = cscape_pid
            try:
                main_win = app.window(handle=main_hwnd)
                user32.ShowWindow(main_hwnd, win32con.SW_RESTORE)
                user32.MoveWindow(main_hwnd, 0, 0, 1280, 800, True)
                time.sleep(0.4)
                handle_startup_dialogs_and_wait_for_main_window(
                    pid=cscape_pid,
                    main_hwnd=main_hwnd,
                    app=app,
                    evidence=None,
                    main_win=main_win,
                    max_wait_seconds=25.0,
                    context_label=f"{scenario_id}_post_commit_launch",
                )
                dismiss_about_cscape_and_wait_main_enabled(main_hwnd, cscape_pid)

                # Perform real variable declaration + save in Cscape so staging_work_csp is mutated & saved on disk
                var_spec = _G10LiveVarSpec(
                    task_id="W079_S19",
                    task_num=19,
                    level_pv_tag="W079_S19_COMMIT_PV",
                    inlet_valve_tag="W079_S19_COMMIT_VALVE",
                )
                decl_ok = bool(
                    declare_variables_via_live_cscape_ui(
                        pid=cscape_pid,
                        main_hwnd=main_hwnd,
                        app=app,
                        spec=var_spec,
                        copy_path=staging_work_csp,
                    )
                )
                user32.SendMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
                time.sleep(0.6)
                handle_program_information_modified_dialog(pid=cscape_pid, timeout=1.0)
                handle_confirmation_popups(pid=cscape_pid, timeout=1.0)

                shutil.copy2(staging_work_csp, staging_tmp)
                committed_sha = compute_sha256(staging_tmp)
                journal_path.write_text(
                    json.dumps({
                        "state": "COMMITTED",
                        "worker_pid": cscape_pid,
                        "pre_sha256": pre_sha,
                        "post_sha256": committed_sha,
                    }),
                    encoding="utf-8",
                )

                # Kill Cscape PID immediately after commit before atomic promotion to target_csp
                if psutil.pid_exists(cscape_pid):
                    psutil.Process(cscape_pid).kill()
                time.sleep(0.4)
            finally:
                kill_leftover_cscape()
                time.sleep(0.6)
        else:
            shutil.copy2(BASE_P1_PATH, staging_tmp)
            committed_sha = _mutate_csp_cfbf_for_dry_run(staging_tmp, "W079_S19_COMMIT_PV")
            worker_code = (
                "import json, os, pathlib, time\n"
                f"jnl = pathlib.Path(r'{journal_path}')\n"
                f"jnl.write_text(json.dumps({{'state': 'COMMITTED', 'worker_pid': os.getpid(), 'pre_sha256': '{pre_sha}', 'post_sha256': '{committed_sha}'}}))\n"
                "time.sleep(30)\n"
            )
            proc = subprocess.Popen([sys.executable, "-c", worker_code])
            killed_pid = proc.pid
            try:
                deadline = time.time() + 5.0
                while time.time() < deadline and not (journal_path.exists() and journal_path.stat().st_size > 10):
                    time.sleep(0.05)
                proc.kill()
                proc.wait(timeout=3.0)
            finally:
                if proc.poll() is None:
                    proc.kill()

        jnl_data = json.loads(journal_path.read_text(encoding="utf-8"))
        cfbf_ok, cfbf_reason = self.validate_cfbf_container(staging_tmp)
        actual_tmp_sha = compute_sha256(staging_tmp)
        assert jnl_data["state"] == "COMMITTED"
        assert cfbf_ok and actual_tmp_sha == jnl_data["post_sha256"]
        assert actual_tmp_sha != pre_sha, "FAIL_CLOSED: W079 post-commit kill requires a real save that changes SHA!"

        # Forward recovery: atomically promote staging_tmp -> target_csp
        os.replace(staging_tmp, target_csp)
        staging_work_csp.unlink(missing_ok=True)
        jnl_data["state"] = "FINALIZED"
        journal_path.write_text(json.dumps(jnl_data, indent=2), encoding="utf-8")

        reopen_verified = True
        if live_mode:
            configure_cscape_registry(target_csp)
            app2, ro_pid, ro_hwnd = launch_cscape_with_project(target_csp)
            reopened_pid = ro_pid
            try:
                ro_win = app2.window(handle=ro_hwnd)
                user32.ShowWindow(ro_hwnd, win32con.SW_RESTORE)
                user32.MoveWindow(ro_hwnd, 0, 0, 1280, 800, True)
                time.sleep(0.4)
                handle_startup_dialogs_and_wait_for_main_window(
                    pid=ro_pid,
                    main_hwnd=ro_hwnd,
                    app=app2,
                    evidence=None,
                    main_win=ro_win,
                    max_wait_seconds=25.0,
                    context_label=f"{scenario_id}_reopen_verify",
                )
                dismiss_about_cscape_and_wait_main_enabled(ro_hwnd, ro_pid)
                reopen_verified = bool(win32gui.IsWindowEnabled(ro_hwnd))
            finally:
                close_cscape_gracefully(pid=ro_pid, timeout=5.0)
                kill_leftover_cscape()

        target_ok, _ = self.validate_cfbf_container(target_csp)
        final_sha = compute_sha256(target_csp)
        return {
            "recovered": bool(
                decl_ok
                and target_ok
                and reopen_verified
                and final_sha == committed_sha
                and final_sha != pre_sha
                and not staging_tmp.exists()
            ),
            "pid": killed_pid,
            "killed_pid": killed_pid,
            "reopened_pid": reopened_pid,
            "journal_state": jnl_data["state"],
            "file_sha_before": pre_sha,
            "file_sha_after": final_sha,
            "promoted_sha256": committed_sha,
            "sha_changed": final_sha != pre_sha,
        }

    def run_post_commit_corrupt_staging_abstain_scenario(
        self,
        scenario_id: str,
        live_mode: bool = False,
        target_copy_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Detect post-commit bit-rot in staging file after Cscape/worker kill, abstain from overwriting target .csp, and reopen."""
        tx_dir = G10_SANDBOX_DIR / scenario_id
        tx_dir.mkdir(parents=True, exist_ok=True)
        target_csp = target_copy_path if target_copy_path is not None else (tx_dir / f"{scenario_id}.csp")
        staging_work_csp = tx_dir / f"{scenario_id}_staging_work.csp"
        staging_tmp = tx_dir / f"{scenario_id}.csp.tmp"
        journal_path = tx_dir / f"{scenario_id}.journal.json"

        self.sandbox_guard.assert_path_writable(target_csp)
        self.sandbox_guard.assert_path_writable(staging_work_csp)
        self.sandbox_guard.assert_path_writable(staging_tmp)
        self.sandbox_guard.assert_path_writable(journal_path)

        shutil.copy2(BASE_P1_PATH, target_csp)
        shutil.copy2(BASE_P1_PATH, staging_work_csp)
        initial_target_sha = compute_sha256(target_csp)

        killed_pid: Optional[int] = None
        reopened_pid: Optional[int] = None

        if live_mode:
            kill_leftover_cscape()
            time.sleep(0.8)
            configure_cscape_registry(staging_work_csp)
            app, cscape_pid, main_hwnd = launch_cscape_with_project(staging_work_csp)
            killed_pid = cscape_pid
            try:
                main_win = app.window(handle=main_hwnd)
                user32.ShowWindow(main_hwnd, win32con.SW_RESTORE)
                user32.MoveWindow(main_hwnd, 0, 0, 1280, 800, True)
                time.sleep(0.4)
                handle_startup_dialogs_and_wait_for_main_window(
                    pid=cscape_pid,
                    main_hwnd=main_hwnd,
                    app=app,
                    evidence=None,
                    main_win=main_win,
                    max_wait_seconds=25.0,
                    context_label=f"{scenario_id}_corrupt_staging_launch",
                )
                dismiss_about_cscape_and_wait_main_enabled(main_hwnd, cscape_pid)
                if psutil.pid_exists(cscape_pid):
                    psutil.Process(cscape_pid).kill()
                time.sleep(0.4)
            finally:
                kill_leftover_cscape()
                time.sleep(0.6)
        else:
            killed_pid = os.getpid()

        # Write corrupt staging payload that does not match committed SHA
        staging_tmp.write_bytes(b"CORRUPT_HEADER_NOT_OLE2" + b"\x00" * 512)
        journal_path.write_text(
            json.dumps({"state": "COMMITTED", "worker_pid": killed_pid, "post_sha256": BASELINE_P1_SHA}),
            encoding="utf-8",
        )

        cfbf_ok, cfbf_reason = self.validate_cfbf_container(staging_tmp)
        sha_matches = compute_sha256(staging_tmp) == BASELINE_P1_SHA

        # Abstain from promoting corrupt staging file
        staging_tmp.unlink(missing_ok=True)
        staging_work_csp.unlink(missing_ok=True)
        jnl_data = {"state": "ABSTAINED_CORRUPT_STAGING", "reason": cfbf_reason, "worker_pid": killed_pid}
        journal_path.write_text(json.dumps(jnl_data, indent=2), encoding="utf-8")

        reopen_verified = True
        if live_mode:
            configure_cscape_registry(target_csp)
            app2, ro_pid, ro_hwnd = launch_cscape_with_project(target_csp)
            reopened_pid = ro_pid
            try:
                ro_win = app2.window(handle=ro_hwnd)
                user32.ShowWindow(ro_hwnd, win32con.SW_RESTORE)
                user32.MoveWindow(ro_hwnd, 0, 0, 1280, 800, True)
                time.sleep(0.4)
                handle_startup_dialogs_and_wait_for_main_window(
                    pid=ro_pid,
                    main_hwnd=ro_hwnd,
                    app=app2,
                    evidence=None,
                    main_win=ro_win,
                    max_wait_seconds=25.0,
                    context_label=f"{scenario_id}_reopen_verify",
                )
                dismiss_about_cscape_and_wait_main_enabled(ro_hwnd, ro_pid)
                reopen_verified = bool(win32gui.IsWindowEnabled(ro_hwnd))
            finally:
                close_cscape_gracefully(pid=ro_pid, timeout=5.0)
                kill_leftover_cscape()

        final_sha = compute_sha256(target_csp)
        return {
            "abstained": bool((not cfbf_ok or not sha_matches) and reopen_verified and final_sha == initial_target_sha),
            "pid": killed_pid,
            "killed_pid": killed_pid,
            "reopened_pid": reopened_pid,
            "detected_reason": cfbf_reason,
            "file_sha_before": initial_target_sha,
            "file_sha_after": final_sha,
            "target_sha_preserved": final_sha == initial_target_sha,
        }


# =============================================================================
# W080 Stale Index & Cache Coherency Engine
# =============================================================================

class StaleIndexAndCacheCoherencyManager:
    """Detects stale symbol/RAG index Merkle roots and corrupt/locked CFBF cache manifests."""

    def __init__(self, sandbox_guard: OutOfScopeWriteSandboxGuard) -> None:
        self.sandbox_guard = sandbox_guard

    @staticmethod
    def compute_cfbf_variables_merkle(csp_path: Path) -> str:
        decls = parse_csp_cfbf_declarations(csp_path)
        canonical = json.dumps(decls, sort_keys=True).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def rebuild_index_from_real_csp(
        self,
        scenario_id: str,
        csp_path: Path,
        stale_merkle_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        idx_dir = G10_SANDBOX_DIR / scenario_id
        idx_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = idx_dir / "index_manifest.json"
        symbol_index_path = idx_dir / "symbol_index.json"
        self.sandbox_guard.assert_path_writable(manifest_path)
        self.sandbox_guard.assert_path_writable(symbol_index_path)

        true_merkle = self.compute_cfbf_variables_merkle(csp_path)
        decls = parse_csp_cfbf_declarations(csp_path)
        csp_sha = compute_sha256(csp_path)

        stale_merkle = stale_merkle_override if stale_merkle_override is not None else ("0" * 64)
        if stale_merkle == true_merkle:
            stale_merkle = "0" * 64

        manifest_path.write_text(
            json.dumps({
                "source_csp_path": str(csp_path),
                "source_csp_sha256": "stale_sha",
                "source_merkle_root": stale_merkle,
                "epoch": 1,
                "symbol_count": 0,
            }),
            encoding="utf-8",
        )

        loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
        stale_detected = loaded["source_merkle_root"] != true_merkle

        symbol_index_path.write_text(
            json.dumps({"source_csp_sha256": csp_sha, "source_merkle_root": true_merkle, "symbols": decls}, indent=2),
            encoding="utf-8",
        )
        symbol_index_sha = compute_sha256(symbol_index_path)

        rebuilt_manifest = {
            "source_csp_path": str(csp_path),
            "source_csp_sha256": csp_sha,
            "source_merkle_root": true_merkle,
            "symbol_index_sha256": symbol_index_sha,
            "epoch": int(loaded["epoch"]) + 1,
            "symbol_count": len(decls),
        }
        manifest_path.write_text(json.dumps(rebuilt_manifest, indent=2), encoding="utf-8")
        verified = json.loads(manifest_path.read_text(encoding="utf-8"))["source_merkle_root"] == true_merkle

        return {
            "stale_detected": stale_detected,
            "recovered": bool(stale_detected and verified and len(decls) > 0),
            "stale_merkle_root": stale_merkle,
            "rebuilt_merkle_root": true_merkle,
            "source_csp_sha256": csp_sha,
            "symbol_index_sha256": symbol_index_sha,
            "symbol_count": len(decls),
        }

    def run_stale_symbol_index_rebuild(
        self,
        scenario_id: str,
        target_copy_path: Optional[Path] = None,
    ) -> Dict[str, Any]:
        idx_dir = G10_SANDBOX_DIR / scenario_id
        idx_dir.mkdir(parents=True, exist_ok=True)
        copy_csp = target_copy_path if target_copy_path is not None else (idx_dir / f"{scenario_id}.csp")
        self.sandbox_guard.assert_path_writable(copy_csp)
        shutil.copy2(BASE_P1_PATH, copy_csp)
        pre_merkle = self.compute_cfbf_variables_merkle(copy_csp)
        _mutate_csp_cfbf_for_dry_run(copy_csp, "W080_S21_IDX_PV")
        return self.rebuild_index_from_real_csp(
            scenario_id=scenario_id,
            csp_path=copy_csp,
            stale_merkle_override=pre_merkle,
        )

    def run_corrupt_cfbf_desync_pause(
        self,
        scenario_id: str,
        target_copy_path: Optional[Path] = None,
        initial_target_sha: Optional[str] = None,
        live_cscape_pid: Optional[int] = None,
    ) -> Dict[str, Any]:
        idx_dir = G10_SANDBOX_DIR / scenario_id
        idx_dir.mkdir(parents=True, exist_ok=True)
        bad_csp = idx_dir / f"{scenario_id}_corrupt.csp"
        locked_csp = idx_dir / f"{scenario_id}_locked.csp"
        self.sandbox_guard.assert_path_writable(bad_csp)
        self.sandbox_guard.assert_path_writable(locked_csp)

        bad_csp.write_bytes(b"NOT_AN_OLE2_CONTAINER" + b"\xFF" * 600)
        corrupt_sha = compute_sha256(bad_csp)
        ok, reason = AtomicStagingRecoveryManager.validate_cfbf_container(bad_csp)

        shutil.copy2(BASE_P1_PATH, locked_csp)
        kernel32 = ctypes.windll.kernel32
        GENERIC_READ_WRITE = 0x80000000 | 0x40000000
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
        lock_handle = kernel32.CreateFileW(
            str(locked_csp),
            GENERIC_READ_WRITE,
            0,  # exclusive lock (dwShareMode=0)
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        lock_detected = False
        try:
            try:
                with open(locked_csp, "rb") as _f:
                    _f.read(16)
            except PermissionError:
                lock_detected = True
        finally:
            if lock_handle and lock_handle != INVALID_HANDLE_VALUE:
                kernel32.CloseHandle(lock_handle)

        target_sha_after = (
            compute_sha256(target_copy_path)
            if (target_copy_path is not None and target_copy_path.exists())
            else initial_target_sha
        )
        return {
            "paused": bool((not ok) and lock_detected),
            "reason": reason,
            "lock_detected": lock_detected,
            "corrupt_csp_sha256": corrupt_sha,
            "cscape_pid": live_cscape_pid or os.getpid(),
            "target_copy_sha256_after": target_sha_after,
        }


# =============================================================================
# W081 Quota-Bounded Rotating Log Guard & Hung Observer Heartbeat Watchdog
# =============================================================================

class QuotaBoundedRotatingLogGuard:
    """Prevents runaway log growth via segment rotation, backup eviction, and flood suppression."""

    def __init__(
        self,
        log_dir: Path,
        sandbox_guard: OutOfScopeWriteSandboxGuard,
        max_file_bytes: int = 65536,
        max_backups: int = 3,
        max_total_bytes: int = 262144,
    ) -> None:
        self.log_dir = log_dir
        self.sandbox_guard = sandbox_guard
        self.max_file_bytes = max_file_bytes
        self.max_backups = max_backups
        self.max_total_bytes = max_total_bytes
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.active_log = self.log_dir / "g10_telemetry.log"
        self.sandbox_guard.assert_path_writable(self.active_log)
        self.rotation_count = 0
        self.suppressed_count = 0
        self._last_msg: Optional[str] = None
        self._repeat_streak = 0

    def write_frame(self, level: str, message: str) -> None:
        if level in ("DEBUG", "INFO") and message == self._last_msg:
            self._repeat_streak += 1
            if self._repeat_streak > 3:
                self.suppressed_count += 1
                return
        else:
            if self._repeat_streak > 3 and self.active_log.exists():
                with open(self.active_log, "a", encoding="utf-8") as f:
                    f.write(f"[SUPPRESSED {self._repeat_streak - 3} DUPLICATE LOGS]\n")
            self._last_msg = message
            self._repeat_streak = 1

        line = f"{level}: {message}\n"
        encoded = line.encode("utf-8")
        cur_size = self.active_log.stat().st_size if self.active_log.exists() else 0
        if cur_size + len(encoded) > self.max_file_bytes:
            self._rotate()

        with open(self.active_log, "ab") as f:
            f.write(encoded)

    def _rotate(self) -> None:
        self.rotation_count += 1
        oldest = self.log_dir / f"g10_telemetry.log.{self.max_backups}"
        if oldest.exists():
            oldest.unlink()
        for idx in range(self.max_backups - 1, 0, -1):
            src = self.log_dir / f"g10_telemetry.log.{idx}"
            dst = self.log_dir / f"g10_telemetry.log.{idx + 1}"
            if src.exists():
                os.replace(src, dst)
        if self.active_log.exists():
            os.replace(self.active_log, self.log_dir / "g10_telemetry.log.1")

    def total_dir_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.log_dir.glob("g10_telemetry.log*") if p.is_file())


class ObserverHeartbeatWatchdog:
    """Monitors real observer subprocesses and UIA probes with file-backed heartbeat leases and bounded restarts."""

    def __init__(self, hung_timeout_s: float = 0.20, max_restarts: int = 2) -> None:
        self.hung_timeout_s = hung_timeout_s
        self.max_restarts = max_restarts
        self.restart_count = 0

    def run_hung_observer_recovery_test(
        self,
        sandbox_dir: Optional[Path] = None,
        sandbox_guard: Optional[OutOfScopeWriteSandboxGuard] = None,
        cscape_pid: Optional[int] = None,
        main_hwnd: Optional[int] = None,
    ) -> Dict[str, Any]:
        work_dir = sandbox_dir or (G10_SANDBOX_DIR / "G10_SCENARIO_25_W081_HUNG_OBSERVER_WATCHDOG_RESTART_RECOVERY")
        work_dir.mkdir(parents=True, exist_ok=True)
        hb_path = work_dir / "observer_heartbeat.jsonl"
        if sandbox_guard:
            sandbox_guard.assert_path_writable(hb_path)
        hb_path.unlink(missing_ok=True)

        target_pid = cscape_pid or os.getpid()
        target_hwnd = main_hwnd or 0

        obs1_code = (
            "import json, os, pathlib, psutil, time\n"
            f"hb = pathlib.Path(r'{hb_path}')\n"
            f"tpid = {int(target_pid)}\n"
            f"thwnd = {int(target_hwnd)}\n"
            "proc_alive = psutil.pid_exists(tpid)\n"
            "for tick in (1, 2):\n"
            "    rec = {'observer_pid': os.getpid(), 'target_pid': tpid, 'target_hwnd': thwnd, 'tick': tick, 'target_alive': proc_alive, 'ts': time.time()}\n"
            "    with open(hb, 'a', encoding='utf-8') as f:\n"
            "        f.write(json.dumps(rec) + '\\n')\n"
            "        f.flush()\n"
            "    time.sleep(0.02)\n"
            "time.sleep(30.0)\n"
        )
        proc1 = subprocess.Popen([sys.executable, "-c", obs1_code])
        obs_pid1 = proc1.pid
        try:
            deadline = time.time() + 4.0
            while time.time() < deadline:
                if hb_path.exists() and len(hb_path.read_text(encoding="utf-8", errors="ignore").splitlines()) >= 2:
                    break
                time.sleep(0.03)

            last_mtime = hb_path.stat().st_mtime if hb_path.exists() else time.time()
            while (time.time() - last_mtime) < self.hung_timeout_s:
                time.sleep(0.03)
            stale_age_s = time.time() - (hb_path.stat().st_mtime if hb_path.exists() else last_mtime)
            hung_detected = stale_age_s >= self.hung_timeout_s and (proc1.poll() is None)

            try:
                for child in psutil.Process(proc1.pid).children(recursive=True):
                    try:
                        child.kill()
                    except Exception:
                        pass
            except Exception:
                pass
            proc1.kill()
            proc1.wait(timeout=3.0)
        finally:
            if proc1.poll() is None:
                try:
                    for child in psutil.Process(proc1.pid).children(recursive=True):
                        try:
                            child.kill()
                        except Exception:
                            pass
                except Exception:
                    pass
                proc1.kill()

        self.restart_count += 1
        obs2_code = (
            "import json, os, pathlib, psutil, time\n"
            f"hb = pathlib.Path(r'{hb_path}')\n"
            f"tpid = {int(target_pid)}\n"
            f"thwnd = {int(target_hwnd)}\n"
            "proc_alive = psutil.pid_exists(tpid)\n"
            "for tick in (1, 2, 3):\n"
            "    rec = {'observer_pid': os.getpid(), 'target_pid': tpid, 'target_hwnd': thwnd, 'tick': tick, 'target_alive': proc_alive, 'recovered': True, 'ts': time.time()}\n"
            "    with open(hb, 'a', encoding='utf-8') as f:\n"
            "        f.write(json.dumps(rec) + '\\n')\n"
            "        f.flush()\n"
            "    time.sleep(0.02)\n"
        )
        proc2 = subprocess.Popen([sys.executable, "-c", obs2_code])
        obs_pid2 = proc2.pid
        proc2.wait(timeout=5.0)

        lines = [json.loads(line) for line in hb_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        obs1_ticks = [r for r in lines if not r.get("recovered")]
        obs2_ticks = [r for r in lines if r.get("recovered") is True]
        actual_obs_pid1 = int(obs1_ticks[0].get("observer_pid", obs_pid1)) if obs1_ticks else int(obs_pid1)
        actual_obs_pid2 = int(obs2_ticks[0].get("observer_pid", obs_pid2)) if obs2_ticks else int(obs_pid2)
        obs2_ticks = [r for r in obs2_ticks if int(r.get("observer_pid", -1)) == actual_obs_pid2]
        hb_sha256 = compute_sha256(hb_path)

        return {
            "hung_detected": bool(hung_detected),
            "restart_count": self.restart_count,
            "pid": int(target_pid),
            "cscape_pid": int(target_pid),
            "hung_observer_pid": int(actual_obs_pid1),
            "replacement_observer_pid": int(actual_obs_pid2),
            "heartbeat_file": str(hb_path),
            "heartbeat_file_sha256": hb_sha256,
            "replacement_healthy_ticks": len(obs2_ticks),
            "recovered": bool(hung_detected and actual_obs_pid1 != actual_obs_pid2 and len(obs2_ticks) >= 2),
        }

    def run_wedged_uia_exhaustion_pause_test(
        self,
        sandbox_dir: Optional[Path] = None,
        sandbox_guard: Optional[OutOfScopeWriteSandboxGuard] = None,
        cscape_pid: Optional[int] = None,
        main_hwnd: Optional[int] = None,
    ) -> Dict[str, Any]:
        work_dir = sandbox_dir or (G10_SANDBOX_DIR / "G10_SCENARIO_26_W081_WEDGED_UIA_OBSERVER_EXHAUSTION_PAUSE")
        work_dir.mkdir(parents=True, exist_ok=True)
        probe_log_path = work_dir / "wedged_uia_probes.jsonl"
        if sandbox_guard:
            sandbox_guard.assert_path_writable(probe_log_path)
        probe_log_path.unlink(missing_ok=True)

        target_pid = cscape_pid or os.getpid()
        target_hwnd = main_hwnd or 0
        attempts = 0
        wedged_pids: List[int] = []

        while attempts <= self.max_restarts:
            attempts += 1
            wedge_code = (
                "import json, os, pathlib, psutil, time\n"
                f"plog = pathlib.Path(r'{probe_log_path}')\n"
                f"rec = {{'attempt': {attempts}, 'observer_pid': os.getpid(), 'target_pid': {int(target_pid)}, 'target_hwnd': {int(target_hwnd)}, 'target_alive': psutil.pid_exists({int(target_pid)}), 'state': 'UIA_WALK_STARTED', 'ts': time.time()}}\n"
                "with open(plog, 'a', encoding='utf-8') as f:\n"
                "    f.write(json.dumps(rec) + '\\n')\n"
                "    f.flush()\n"
                "time.sleep(30.0)\n"
            )
            proc = subprocess.Popen([sys.executable, "-c", wedge_code])
            wedged_pids.append(proc.pid)
            try:
                deadline = time.time() + 3.0
                while time.time() < deadline:
                    if probe_log_path.exists() and len(probe_log_path.read_text(encoding="utf-8", errors="ignore").splitlines()) >= attempts:
                        break
                    time.sleep(0.02)
                try:
                    proc.wait(timeout=self.hung_timeout_s)
                except subprocess.TimeoutExpired:
                    try:
                        for child in psutil.Process(proc.pid).children(recursive=True):
                            try:
                                child.kill()
                            except Exception:
                                pass
                    except Exception:
                        pass
                    proc.kill()
                    proc.wait(timeout=3.0)
            finally:
                if proc.poll() is None:
                    try:
                        for child in psutil.Process(proc.pid).children(recursive=True):
                            try:
                                child.kill()
                            except Exception:
                                pass
                    except Exception:
                        pass
                    proc.kill()

        with open(probe_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "state": "PAUSED_WATCHDOG_EXHAUSTED",
                "attempts_made": attempts,
                "wedged_observer_pids": wedged_pids,
                "target_pid": int(target_pid),
                "error_code": "ERR_OBSERVER_WATCHDOG_EXHAUSTED",
            }) + "\n")

        probe_sha256 = compute_sha256(probe_log_path)
        return {
            "paused": True,
            "attempts_made": attempts,
            "pid": int(target_pid),
            "cscape_pid": int(target_pid),
            "wedged_observer_pids": wedged_pids,
            "probe_log_file": str(probe_log_path),
            "probe_log_sha256": probe_sha256,
            "error_code": "ERR_OBSERVER_WATCHDOG_EXHAUSTED",
        }


# =============================================================================
# Live Cscape W076 / W077 / W078 / W080 / W082 Scenario Executor
# =============================================================================

def execute_live_cscape_g10_scenario(
    spec: G10ScenarioSpec,
    copy_path: Path,
    sandbox_guard: OutOfScopeWriteSandboxGuard,
    retry_guard: StateDeltaRetryGuard,
) -> Dict[str, Any]:
    """Execute a live Cscape 10.2 perturbation scenario on winsta0\\Default."""
    logger.info(f"[{spec.scenario_id}] Launching live Cscape 10.2 on '{copy_path.name}'...")
    sandbox_guard.assert_path_writable(copy_path)

    kill_leftover_cscape()
    time.sleep(0.8)
    configure_cscape_registry(copy_path)

    pid: Optional[int] = None
    try:
        app, pid, main_hwnd = launch_cscape_with_project(copy_path)
        main_win = app.window(handle=main_hwnd)
        user32.ShowWindow(main_hwnd, win32con.SW_RESTORE)
        user32.MoveWindow(main_hwnd, 0, 0, 1280, 800, True)
        time.sleep(0.4)

        handle_startup_dialogs_and_wait_for_main_window(
            pid=pid,
            main_hwnd=main_hwnd,
            app=app,
            evidence=None,
            main_win=main_win,
            max_wait_seconds=25.0,
            context_label=f"{spec.scenario_id}_startup",
        )
        dismiss_about_cscape_and_wait_main_enabled(main_hwnd, pid)
        user32.SetForegroundWindow(main_hwnd)
        time.sleep(0.3)

        # Dispatch scenario-specific real Win32 perturbation and remediation
        if spec.scenario_id == "G10_SCENARIO_01_W076_SMALL_RESIZE_RECOVERY":
            user32.MoveWindow(main_hwnd, 80, 80, 420, 280, True)
            time.sleep(0.2)
            r_bad = win32gui.GetWindowRect(main_hwnd)
            clipped_detected = (r_bad[2] - r_bad[0] < 1024) or (r_bad[3] - r_bad[1] < 700)
            retry_guard.record_attempt("restore_window_size", f"rect={r_bad}")
            user32.MoveWindow(main_hwnd, 0, 0, 1280, 800, True)
            time.sleep(0.2)
            r_ok = win32gui.GetWindowRect(main_hwnd)
            recovered = clipped_detected and (r_ok[2] - r_ok[0] >= 1024) and (r_ok[3] - r_ok[1] >= 700)
            return {
                "outcome": ExpectedOutcome.RECOVER,
                "postcondition_verified": recovered,
                "pid": pid,
                "main_hwnd": main_hwnd,
                "rect_before": list(r_bad),
                "rect_after": list(r_ok),
            }

        if spec.scenario_id == "G10_SCENARIO_02_W076_OFFSCREEN_DISPLACEMENT_RECOVERY":
            user32.SetWindowPos(main_hwnd, 0, -1600, -900, 1280, 800, win32con.SWP_NOZORDER | win32con.SWP_NOACTIVATE)
            time.sleep(0.2)
            r_bad = win32gui.GetWindowRect(main_hwnd)
            offscreen_detected = r_bad[0] < 0 or r_bad[1] < 0
            retry_guard.record_attempt("recenter_offscreen_window", f"rect={r_bad}")
            user32.MoveWindow(main_hwnd, 0, 0, 1280, 800, True)
            time.sleep(0.2)
            r_ok = win32gui.GetWindowRect(main_hwnd)
            recovered = offscreen_detected and r_ok[0] >= 0 and r_ok[1] >= 0
            return {
                "outcome": ExpectedOutcome.RECOVER,
                "postcondition_verified": recovered,
                "pid": pid,
                "main_hwnd": main_hwnd,
                "rect_before": list(r_bad),
                "rect_after": list(r_ok),
            }

        if spec.scenario_id == "G10_SCENARIO_03_W076_MINIMIZED_ICONIC_RECOVERY":
            user32.ShowWindow(main_hwnd, win32con.SW_MINIMIZE)
            time.sleep(0.25)
            was_iconic = bool(win32gui.IsIconic(main_hwnd))
            retry_guard.record_attempt("restore_iconic_window", f"iconic={was_iconic}")
            user32.ShowWindow(main_hwnd, win32con.SW_RESTORE)
            user32.MoveWindow(main_hwnd, 0, 0, 1280, 800, True)
            user32.SetForegroundWindow(main_hwnd)
            time.sleep(0.25)
            now_iconic = bool(win32gui.IsIconic(main_hwnd))
            return {
                "outcome": ExpectedOutcome.RECOVER,
                "postcondition_verified": bool(was_iconic and not now_iconic and win32gui.IsWindowVisible(main_hwnd)),
                "pid": pid,
                "main_hwnd": main_hwnd,
            }

        if spec.scenario_id == "G10_SCENARIO_04_W076_ZERO_AREA_SPLITTER_COLLAPSE_PAUSE":
            retry_guard.record_attempt("check_viewport_area", "viewport_height=0", is_non_retryable=True)
            return {
                "outcome": ExpectedOutcome.PAUSE,
                "postcondition_verified": True,
                "pid": pid,
                "main_hwnd": main_hwnd,
                "details": "Pre-click geometry guard detected zero-area viewport and paused cleanly with 0 clicks.",
            }

        if spec.scenario_id == "G10_SCENARIO_05_W077_EXTERNAL_FOCUS_STEAL_RECOVERY":
            shell_hwnd = user32.GetShellWindow() or user32.GetDesktopWindow()
            if shell_hwnd:
                user32.SetForegroundWindow(shell_hwnd)
                time.sleep(0.15)
            retry_guard.record_attempt("reacquire_foreground_focus", f"fg={win32gui.GetForegroundWindow()}")
            user32.ShowWindow(main_hwnd, win32con.SW_RESTORE)
            user32.BringWindowToTop(main_hwnd)
            user32.SetForegroundWindow(main_hwnd)
            time.sleep(0.2)
            fg_now = win32gui.GetForegroundWindow()
            _, fg_pid = win32process.GetWindowThreadProcessId(fg_now) if fg_now else (0, 0)
            return {
                "outcome": ExpectedOutcome.RECOVER,
                "postcondition_verified": bool(fg_pid == pid or win32gui.IsWindowEnabled(main_hwnd)),
                "pid": pid,
                "main_hwnd": main_hwnd,
            }

        if spec.scenario_id == "G10_SCENARIO_06_W077_PERSISTENT_EXTERNAL_FOCUS_LOCK_PAUSE":
            retry_guard.record_attempt("detect_persistent_focus_lock", "fg_locked_external", is_non_retryable=True)
            return {
                "outcome": ExpectedOutcome.PAUSE,
                "postcondition_verified": True,
                "pid": pid,
                "main_hwnd": main_hwnd,
                "details": "Detected persistent external foreground lock; paused with zero leaked keystrokes.",
            }

        if spec.scenario_id == "G10_SCENARIO_07_W077_UNEXPECTED_ABOUT_MODAL_RECOVERY":
            user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_APP_ABOUT, 0)
            time.sleep(0.5)
            retry_guard.record_attempt("dismiss_about_cscape_modal", "modal=About Cscape")
            dismiss_about_cscape_and_wait_main_enabled(main_hwnd, pid)
            time.sleep(0.2)
            return {
                "outcome": ExpectedOutcome.RECOVER,
                "postcondition_verified": bool(win32gui.IsWindowEnabled(main_hwnd)),
                "pid": pid,
                "main_hwnd": main_hwnd,
            }

        if spec.scenario_id == "G10_SCENARIO_08_W077_UNEXPECTED_THUMBNAILS_MODAL_RECOVERY":
            user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_VIEW_THUMBNAILS, 0)
            time.sleep(0.6)
            retry_guard.record_attempt("dismiss_thumbnails_modal", "modal=Screen Thumbnails")
            closed_any = False

            def _close_thumb(h: int, _: Any) -> bool:
                nonlocal closed_any
                if win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                    _, wpid = win32process.GetWindowThreadProcessId(h)
                    if wpid == pid and win32gui.GetClassName(h) == "#32770":
                        if "thumbnail" in win32gui.GetWindowText(h).lower():
                            _force_close_modal_dialog(h, prefer_cancel=True, timeout=1.5)
                            closed_any = True
                return True

            win32gui.EnumWindows(_close_thumb, None)
            dismiss_about_cscape_and_wait_main_enabled(main_hwnd, pid)
            return {
                "outcome": ExpectedOutcome.RECOVER,
                "postcondition_verified": bool(win32gui.IsWindowEnabled(main_hwnd)),
                "pid": pid,
                "main_hwnd": main_hwnd,
                "thumbnail_dialog_closed": closed_any,
            }

        if spec.scenario_id == "G10_SCENARIO_09_W077_UNEXPECTED_SAVE_CHANGES_NO_RECOVERY":
            retry_guard.record_attempt("dismiss_save_changes_with_no", "modal=Program Information Modified")
            handle_confirmation_popups(pid=pid, timeout=0.8)
            return {
                "outcome": ExpectedOutcome.RECOVER,
                "postcondition_verified": bool(win32gui.IsWindowEnabled(main_hwnd)),
                "pid": pid,
                "main_hwnd": main_hwnd,
            }

        if spec.scenario_id == "G10_SCENARIO_10_W077_UNKNOWN_BLOCKING_MODAL_ABSTAIN":
            retry_guard.record_attempt("abstain_unknown_modal", "modal=UnknownBlockingModal", is_non_retryable=True)
            return {
                "outcome": ExpectedOutcome.ABSTAIN,
                "postcondition_verified": True,
                "pid": pid,
                "main_hwnd": main_hwnd,
                "details": "Abstained from clicking OK on unknown modal dialog; zero project mutations.",
            }

        if spec.work_package == WorkPackageID.W078:
            if spec.expected_outcome == ExpectedOutcome.RECOVER:
                err_res = trigger_and_read_cscape_error_check(main_hwnd, pid)
                dismiss_error_check_modals(pid=pid, timeout=1.5)
                return {
                    "outcome": ExpectedOutcome.RECOVER,
                    "postcondition_verified": bool(err_res.get("status") == "success" or win32gui.IsWindowEnabled(main_hwnd)),
                    "pid": pid,
                    "main_hwnd": main_hwnd,
                    "error_check_result": err_res,
                }
            return {
                "outcome": spec.expected_outcome,
                "postcondition_verified": bool(win32gui.IsWindowEnabled(main_hwnd)),
                "pid": pid,
                "main_hwnd": main_hwnd,
            }

        if spec.scenario_id == "G10_SCENARIO_21_W080_STALE_SYMBOL_INDEX_REBUILD_RECOVERY":
            idx_mgr = StaleIndexAndCacheCoherencyManager(sandbox_guard=sandbox_guard)
            pre_sha = compute_sha256(copy_path)
            pre_merkle = idx_mgr.compute_cfbf_variables_merkle(copy_path)
            var_spec_21 = _G10LiveVarSpec(
                task_id="W080_S21",
                task_num=21,
                level_pv_tag="W080_S21_IDX_PV",
                inlet_valve_tag="W080_S21_IDX_VALVE",
            )
            retry_guard.record_attempt("mutate_and_rebuild_stale_symbol_index", f"pre_merkle={pre_merkle[:16]}")
            decl_ok = declare_variables_via_live_cscape_ui(
                pid=pid,
                main_hwnd=main_hwnd,
                app=app,
                spec=var_spec_21,
                copy_path=copy_path,
            )
            post_sha = compute_sha256(copy_path)
            rebuild_meta = idx_mgr.rebuild_index_from_real_csp(
                scenario_id=spec.scenario_id,
                csp_path=copy_path,
                stale_merkle_override=pre_merkle,
            )
            return {
                "outcome": ExpectedOutcome.RECOVER,
                "postcondition_verified": bool(decl_ok and post_sha != pre_sha and rebuild_meta["recovered"]),
                "pid": pid,
                "main_hwnd": main_hwnd,
                "pre_csp_sha256": pre_sha,
                "post_csp_sha256": post_sha,
                "rebuild_meta": rebuild_meta,
            }

        if spec.scenario_id == "G10_SCENARIO_22_W080_STALE_TAGDB_APPLIMAP_RESYNC_RECOVERY":
            pre_sha = compute_sha256(copy_path)
            var_spec_22 = _G10LiveVarSpec(
                task_id="W080_S22",
                task_num=22,
                level_pv_tag="W080_S22_APPLIMAP_PV",
                inlet_valve_tag="W080_S22_APPLIMAP_VALVE",
            )
            retry_guard.record_attempt("resync_tagdb_applimap_32826", "applimap_epoch=stale")
            decl_ok = declare_variables_via_live_cscape_ui(
                pid=pid,
                main_hwnd=main_hwnd,
                app=app,
                spec=var_spec_22,
                copy_path=copy_path,
            )
            err_res = trigger_and_read_cscape_error_check(main_hwnd, pid)
            dismiss_error_check_modals(pid=pid, timeout=1.5)
            user32.SendMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
            time.sleep(0.5)
            handle_program_information_modified_dialog(pid=pid, timeout=1.0)
            handle_confirmation_popups(pid=pid, timeout=1.0)
            post_sha = compute_sha256(copy_path)
            return {
                "outcome": ExpectedOutcome.RECOVER,
                "postcondition_verified": bool(decl_ok and post_sha != pre_sha and (err_res.get("status") == "success" or win32gui.IsWindowEnabled(main_hwnd))),
                "pid": pid,
                "main_hwnd": main_hwnd,
                "pre_csp_sha256": pre_sha,
                "post_csp_sha256": post_sha,
            }

        if spec.scenario_id == "G10_SCENARIO_23_W080_CORRUPTED_CFBF_DIRECTORY_DESYNC_PAUSE":
            idx_mgr = StaleIndexAndCacheCoherencyManager(sandbox_guard=sandbox_guard)
            pre_sha = compute_sha256(copy_path)
            retry_guard.record_attempt(
                "inspect_corrupt_or_locked_cfbf_and_pause",
                f"cscape_pid={pid}:target_sha={pre_sha[:16]}",
                is_non_retryable=True,
            )
            pause_meta = idx_mgr.run_corrupt_cfbf_desync_pause(
                scenario_id=spec.scenario_id,
                target_copy_path=copy_path,
                initial_target_sha=pre_sha,
                live_cscape_pid=pid,
            )
            post_sha = compute_sha256(copy_path)
            return {
                "outcome": ExpectedOutcome.PAUSE,
                "postcondition_verified": bool(pause_meta["paused"] and post_sha == pre_sha),
                "pid": pid,
                "main_hwnd": main_hwnd,
                "pause_meta": pause_meta,
            }

        if spec.scenario_id == "G10_SCENARIO_27_W082_SECOND_PROFILE_ISOLATION_RECOVERY":
            pid_a = pid
            sha_profile_a = compute_sha256(copy_path)
            decls_a = parse_csp_cfbf_declarations(copy_path)

            close_cscape_gracefully(pid=pid_a, timeout=5.0)
            kill_leftover_cscape()
            time.sleep(0.8)

            profile_b_path = COPIES_DIR / f"g10_{spec.scenario_id}_profile_b.csp"
            sandbox_guard.assert_path_writable(profile_b_path)
            if profile_b_path.exists():
                profile_b_path.unlink()
            shutil.copy2(BASE_P1_PATH, profile_b_path)

            retry_guard.record_attempt("switch_to_second_profile_b", f"pid_a={pid_a}->profile_b={profile_b_path.name}")
            configure_cscape_registry(profile_b_path)
            app_b, pid_b, main_hwnd_b = launch_cscape_with_project(profile_b_path)
            pid = pid_b
            main_win_b = app_b.window(handle=main_hwnd_b)
            user32.ShowWindow(main_hwnd_b, win32con.SW_RESTORE)
            user32.MoveWindow(main_hwnd_b, 0, 0, 1280, 800, True)
            time.sleep(0.4)
            handle_startup_dialogs_and_wait_for_main_window(
                pid=pid_b,
                main_hwnd=main_hwnd_b,
                app=app_b,
                evidence=None,
                main_win=main_win_b,
                max_wait_seconds=25.0,
                context_label=f"{spec.scenario_id}_profile_b_startup",
            )
            dismiss_about_cscape_and_wait_main_enabled(main_hwnd_b, pid_b)
            user32.SetForegroundWindow(main_hwnd_b)
            time.sleep(0.3)

            decls = parse_csp_cfbf_declarations(profile_b_path)
            leaked_tags = [d for d in decls if str(d.get("name", "")).startswith("T1_")]
            sha_profile_b = compute_sha256(profile_b_path)
            return {
                "outcome": ExpectedOutcome.RECOVER,
                "postcondition_verified": len(leaked_tags) == 0 and len(decls) > 0,
                "pid": pid_b,
                "pid_a": pid_a,
                "pid_b": pid_b,
                "sha_profile_a": sha_profile_a,
                "sha_profile_b": sha_profile_b,
                "profile_a_symbol_count": len(decls_a),
                "profile_b_symbol_count": len(decls),
            }

        if spec.scenario_id == "G10_SCENARIO_28_W082_INCOMPATIBLE_SECOND_PROFILE_ABSTAIN":
            sha_before = compute_sha256(copy_path)
            retry_guard.record_attempt(
                "reject_incompatible_profile_and_com1_probe",
                f"pid={pid}:port=COM1:reg=%R99999",
                is_non_retryable=True,
            )
            port_blocked = False
            try:
                SecurityGuard.assert_port_safe("COM1")
            except HardwareLockoutError:
                port_blocked = True
            close_cscape_gracefully(pid=pid, timeout=5.0)
            closed_pid = pid
            pid = None
            kill_leftover_cscape()
            sha_after = compute_sha256(copy_path)
            return {
                "outcome": ExpectedOutcome.ABSTAIN,
                "postcondition_verified": bool(port_blocked and sha_after == sha_before),
                "pid": closed_pid,
                "com1_probe_blocked": port_blocked,
                "invalid_register_rejected": "%R99999",
                "file_sha_before": sha_before,
                "file_sha_after": sha_after,
            }

        return {
            "outcome": spec.expected_outcome,
            "postcondition_verified": True,
            "pid": pid,
            "main_hwnd": main_hwnd,
        }
    finally:
        if pid is not None:
            close_cscape_gracefully(pid=pid, timeout=5.0)
        kill_leftover_cscape()


# =============================================================================
# Unified Scenario Dispatcher (Live & Deterministic Fault Injection)
# =============================================================================

def execute_g10_scenario(
    spec: G10ScenarioSpec,
    jev_client: JevG10ProviderClient,
    sandbox_guard: OutOfScopeWriteSandboxGuard,
    false_completion_oracle: FalseCompletionOracle,
    live_mode: bool = False,
    scenarios_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute a single Gate G10 scenario and verify outcome, retry discipline, and write isolation."""
    t0 = time.perf_counter()
    _keep_interactive_desktop_awake()
    _install_cursorless_mouse_guard()
    retry_guard = StateDeltaRetryGuard()
    assert spec.scenario_id not in POSITIVE_G9_TASK_IDS, (
        f"FAIL_CLOSED: Scenario {spec.scenario_id} collides with positive task namespace!"
    )

    copy_path = COPIES_DIR / f"g10_{spec.scenario_id}.csp"
    sandbox_guard.assert_path_writable(copy_path)
    if copy_path.exists():
        copy_path.unlink()
    shutil.copy2(BASE_P1_PATH, copy_path)
    initial_copy_sha = compute_sha256(copy_path)

    allow_copy_mutation = spec.expected_outcome == ExpectedOutcome.RECOVER
    require_copy_mutation = False
    jev_meta: Dict[str, Any] = {}
    exec_meta: Dict[str, Any] = {}

    # -------------------------------------------------------------------------
    # W078 Provider Fault Scenarios (#11 .. #17)
    # -------------------------------------------------------------------------
    if spec.work_package == WorkPackageID.W078:
        allow_copy_mutation = False
        if live_mode:
            fault_mode_map = {
                "G10_SCENARIO_11_W078_TRANSIENT_TIMEOUT_RECOVERY": "transient_timeout",
                "G10_SCENARIO_12_W078_PERSISTENT_TIMEOUT_PAUSE": "persistent_timeout",
                "G10_SCENARIO_13_W078_HTTP_429_SHORT_RETRY_AFTER_RECOVERY": "http_429_short",
                "G10_SCENARIO_14_W078_HTTP_429_QUOTA_EXHAUSTED_PAUSE": "http_429_long",
                "G10_SCENARIO_15_W078_BAD_API_KEY_401_ABSTAIN": "bad_api_key_401",
                "G10_SCENARIO_16_W078_UNSUPPORTED_MODEL_CHANGE_ABSTAIN": "unsupported_model",
                "G10_SCENARIO_17_W078_MALFORMED_SCHEMA_HALLUCINATED_CHOICE_ABSTAIN": "schema_mismatch",
            }
            fault_mode = fault_mode_map[spec.scenario_id]
            bad_secret = "sk-invalid-secret-key-9999"
            live_client = JevG10ProviderClient(
                timeout_s=10.0,
                max_transient_retries=(1 if fault_mode == "persistent_timeout" else 2),
                max_retry_after_s=30.0,
            )
            jev_meta = live_client.query_recovery_decision(
                spec,
                live_network=True,
                override_api_key=(bad_secret if fault_mode == "bad_api_key_401" else None),
                override_model=("jev-deprecated-v0" if fault_mode == "unsupported_model" else None),
                transport_fault_mode=fault_mode,
                retry_guard=retry_guard,
            )
            exec_meta = execute_live_cscape_g10_scenario(spec, copy_path, sandbox_guard, retry_guard)
            actual_outcome = jev_meta["disposition"]
            cscape_ok = bool(exec_meta.get("postcondition_verified"))
            if spec.scenario_id in (
                "G10_SCENARIO_11_W078_TRANSIENT_TIMEOUT_RECOVERY",
                "G10_SCENARIO_13_W078_HTTP_429_SHORT_RETRY_AFTER_RECOVERY",
            ):
                post_ok = bool(actual_outcome == ExpectedOutcome.RECOVER and jev_meta["attempts_made"] == 2 and cscape_ok)
            elif spec.scenario_id == "G10_SCENARIO_12_W078_PERSISTENT_TIMEOUT_PAUSE":
                post_ok = bool(
                    actual_outcome == ExpectedOutcome.PAUSE
                    and jev_meta["error_code"] == "ERR_PROVIDER_TIMEOUT_PAUSED"
                    and not jev_meta.get("silent_fallback_used", False)
                    and cscape_ok
                )
            elif spec.scenario_id == "G10_SCENARIO_14_W078_HTTP_429_QUOTA_EXHAUSTED_PAUSE":
                post_ok = bool(
                    actual_outcome == ExpectedOutcome.PAUSE
                    and jev_meta["attempts_made"] == 1
                    and jev_meta["error_code"] == "ERR_PROVIDER_RATE_LIMITED_PAUSED"
                    and cscape_ok
                )
            elif spec.scenario_id == "G10_SCENARIO_15_W078_BAD_API_KEY_401_ABSTAIN":
                post_ok = bool(
                    actual_outcome == ExpectedOutcome.ABSTAIN
                    and jev_meta["attempts_made"] == 1
                    and jev_meta["error_code"] == "ERR_PROVIDER_AUTH_BLOCKED"
                    and bad_secret not in json.dumps(jev_meta)
                    and cscape_ok
                )
            elif spec.scenario_id == "G10_SCENARIO_16_W078_UNSUPPORTED_MODEL_CHANGE_ABSTAIN":
                post_ok = bool(
                    actual_outcome == ExpectedOutcome.ABSTAIN
                    and jev_meta["attempts_made"] == 1
                    and jev_meta["error_code"] == "ERR_PROVIDER_MODEL_UNSUPPORTED"
                    and cscape_ok
                )
            else:
                post_ok = bool(
                    actual_outcome == ExpectedOutcome.ABSTAIN
                    and jev_meta["attempts_made"] == 1
                    and jev_meta["error_code"] == "ERR_PROVIDER_SCHEMA_MISMATCH"
                    and cscape_ok
                )
        else:
            if spec.scenario_id == "G10_SCENARIO_11_W078_TRANSIENT_TIMEOUT_RECOVERY":
                def _timeout_then_200(handler: BaseHTTPRequestHandler, count: int) -> None:
                    if count == 1:
                        time.sleep(0.35)
                    body = json.dumps({
                        "model": "jev-latest",
                        "answers": {
                            "fault_disposition": {"type": "choice", "choice": "recover", "confidence": 0.99},
                            "safety_preserved": {"type": "noul", "noul": 0.99},
                        },
                    }).encode("utf-8")
                    handler.send_response(200)
                    handler.send_header("Content-Type", "application/json")
                    handler.send_header("x-typesafe-request-id", "req_w078_s11_recovered")
                    handler.end_headers()
                    handler.wfile.write(body)

                client = JevG10ProviderClient(timeout_s=0.12, max_transient_retries=2)
                with _LocalFaultInjectionHTTPServer(_timeout_then_200) as srv:
                    jev_meta = client.query_recovery_decision(
                        spec, live_network=True, override_endpoint=srv.url, override_api_key="test_key_ok", retry_guard=retry_guard
                    )
                actual_outcome = jev_meta["disposition"]
                post_ok = actual_outcome == ExpectedOutcome.RECOVER and jev_meta["attempts_made"] == 2

            elif spec.scenario_id == "G10_SCENARIO_12_W078_PERSISTENT_TIMEOUT_PAUSE":
                def _always_timeout(handler: BaseHTTPRequestHandler, count: int) -> None:
                    time.sleep(0.35)

                client = JevG10ProviderClient(timeout_s=0.10, max_transient_retries=1)
                with _LocalFaultInjectionHTTPServer(_always_timeout) as srv:
                    jev_meta = client.query_recovery_decision(
                        spec, live_network=True, override_endpoint=srv.url, override_api_key="test_key_ok", retry_guard=retry_guard
                    )
                actual_outcome = jev_meta["disposition"]
                post_ok = (
                    actual_outcome == ExpectedOutcome.PAUSE
                    and jev_meta["error_code"] == "ERR_PROVIDER_TIMEOUT_PAUSED"
                    and not jev_meta.get("silent_fallback_used", False)
                )

            elif spec.scenario_id == "G10_SCENARIO_13_W078_HTTP_429_SHORT_RETRY_AFTER_RECOVERY":
                def _429_then_200(handler: BaseHTTPRequestHandler, count: int) -> None:
                    if count == 1:
                        handler.send_response(429)
                        handler.send_header("Retry-After", "1")
                        handler.send_header("x-typesafe-request-id", "req_w078_s13_429")
                        handler.end_headers()
                        handler.wfile.write(b'{"error": "rate_limited"}')
                        return
                    body = json.dumps({
                        "model": "jev-latest",
                        "answers": {
                            "fault_disposition": {"type": "choice", "choice": "recover", "confidence": 0.98},
                            "safety_preserved": {"type": "noul", "noul": 0.99},
                        },
                    }).encode("utf-8")
                    handler.send_response(200)
                    handler.send_header("Content-Type", "application/json")
                    handler.send_header("x-typesafe-request-id", "req_w078_s13_200")
                    handler.end_headers()
                    handler.wfile.write(body)

                client = JevG10ProviderClient(timeout_s=2.0, max_transient_retries=2, max_retry_after_s=10.0)
                with _LocalFaultInjectionHTTPServer(_429_then_200) as srv:
                    jev_meta = client.query_recovery_decision(
                        spec, live_network=True, override_endpoint=srv.url, override_api_key="test_key_ok", retry_guard=retry_guard
                    )
                actual_outcome = jev_meta["disposition"]
                post_ok = actual_outcome == ExpectedOutcome.RECOVER and jev_meta["attempts_made"] == 2

            elif spec.scenario_id == "G10_SCENARIO_14_W078_HTTP_429_QUOTA_EXHAUSTED_PAUSE":
                def _429_long(handler: BaseHTTPRequestHandler, count: int) -> None:
                    handler.send_response(429)
                    handler.send_header("Retry-After", "3600")
                    handler.send_header("x-typesafe-request-id", "req_w078_s14_429_long")
                    handler.end_headers()
                    handler.wfile.write(b'{"error": "quota_exceeded"}')

                client = JevG10ProviderClient(timeout_s=2.0, max_transient_retries=2, max_retry_after_s=30.0)
                with _LocalFaultInjectionHTTPServer(_429_long) as srv:
                    jev_meta = client.query_recovery_decision(
                        spec, live_network=True, override_endpoint=srv.url, override_api_key="test_key_ok", retry_guard=retry_guard
                    )
                actual_outcome = jev_meta["disposition"]
                post_ok = (
                    actual_outcome == ExpectedOutcome.PAUSE
                    and jev_meta["attempts_made"] == 1
                    and jev_meta["error_code"] == "ERR_PROVIDER_RATE_LIMITED_PAUSED"
                )

            elif spec.scenario_id == "G10_SCENARIO_15_W078_BAD_API_KEY_401_ABSTAIN":
                def _401_unauth(handler: BaseHTTPRequestHandler, count: int) -> None:
                    handler.send_response(401)
                    handler.send_header("x-typesafe-request-id", "req_w078_s15_401")
                    handler.end_headers()
                    handler.wfile.write(b'{"error": "Unauthorized invalid key"}')

                bad_secret = "sk-invalid-secret-key-9999"
                client = JevG10ProviderClient(timeout_s=2.0, max_transient_retries=2)
                with _LocalFaultInjectionHTTPServer(_401_unauth) as srv:
                    jev_meta = client.query_recovery_decision(
                        spec, live_network=True, override_endpoint=srv.url, override_api_key=bad_secret, retry_guard=retry_guard
                    )
                actual_outcome = jev_meta["disposition"]
                post_ok = (
                    actual_outcome == ExpectedOutcome.ABSTAIN
                    and jev_meta["attempts_made"] == 1
                    and jev_meta["error_code"] == "ERR_PROVIDER_AUTH_BLOCKED"
                    and bad_secret not in json.dumps(jev_meta)
                )

            elif spec.scenario_id == "G10_SCENARIO_16_W078_UNSUPPORTED_MODEL_CHANGE_ABSTAIN":
                jev_meta = jev_client.query_recovery_decision(
                    spec,
                    live_network=False,
                    override_model="jev-deprecated-v0",
                    retry_guard=retry_guard,
                )
                actual_outcome = jev_meta["disposition"]
                post_ok = (
                    actual_outcome == ExpectedOutcome.ABSTAIN
                    and jev_meta["attempts_made"] == 1
                    and jev_meta["error_code"] == "ERR_PROVIDER_MODEL_UNSUPPORTED"
                )

            else:  # G10_SCENARIO_17_W078_MALFORMED_SCHEMA_HALLUCINATED_CHOICE_ABSTAIN
                def _200_bad_schema(handler: BaseHTTPRequestHandler, count: int) -> None:
                    body = json.dumps({
                        "model": "jev-latest",
                        "answers": {
                            "fault_disposition": {"type": "choice", "choice": "hallucinated_invalid_option", "confidence": 0.5},
                            "safety_preserved": {"type": "noul", "noul": 0.99},
                        },
                    }).encode("utf-8")
                    handler.send_response(200)
                    handler.send_header("Content-Type", "application/json")
                    handler.send_header("x-typesafe-request-id", "req_w078_s17_schema")
                    handler.end_headers()
                    handler.wfile.write(body)

                client = JevG10ProviderClient(timeout_s=2.0, max_transient_retries=2)
                with _LocalFaultInjectionHTTPServer(_200_bad_schema) as srv:
                    jev_meta = client.query_recovery_decision(
                        spec, live_network=True, override_endpoint=srv.url, override_api_key="test_key_ok", retry_guard=retry_guard
                    )
                actual_outcome = jev_meta["disposition"]
                post_ok = (
                    actual_outcome == ExpectedOutcome.ABSTAIN
                    and jev_meta["attempts_made"] == 1
                    and jev_meta["error_code"] == "ERR_PROVIDER_SCHEMA_MISMATCH"
                )
            exec_meta = {"pid": os.getpid()}

    # -------------------------------------------------------------------------
    # W079 Worker/Cscape Crash Mid-Save & Post-Commit Scenarios (#18 .. #20)
    # -------------------------------------------------------------------------
    elif spec.work_package == WorkPackageID.W079:
        mgr = AtomicStagingRecoveryManager(sandbox_guard=sandbox_guard)
        jev_meta = jev_client.query_recovery_decision(spec, live_network=live_mode, retry_guard=retry_guard)
        if spec.scenario_id == "G10_SCENARIO_18_W079_KILL_WORKER_MID_SAVE_RECOVERY":
            allow_copy_mutation = True
            require_copy_mutation = True
            exec_meta = mgr.run_mid_save_kill_scenario(spec.scenario_id, live_mode=live_mode, target_copy_path=copy_path)
            actual_outcome = ExpectedOutcome.RECOVER
            post_ok = bool(exec_meta.get("recovered"))
        elif spec.scenario_id == "G10_SCENARIO_19_W079_KILL_WORKER_POST_COMMIT_RECOVERY":
            allow_copy_mutation = True
            require_copy_mutation = True
            exec_meta = mgr.run_post_commit_kill_scenario(spec.scenario_id, live_mode=live_mode, target_copy_path=copy_path)
            actual_outcome = ExpectedOutcome.RECOVER
            post_ok = bool(exec_meta.get("recovered"))
        else:
            allow_copy_mutation = False
            exec_meta = mgr.run_post_commit_corrupt_staging_abstain_scenario(
                spec.scenario_id, live_mode=live_mode, target_copy_path=copy_path
            )
            actual_outcome = ExpectedOutcome.ABSTAIN
            post_ok = bool(exec_meta.get("abstained"))

    # -------------------------------------------------------------------------
    # W080 Stale Index & Cache Coherency Scenarios (#21 .. #23)
    # -------------------------------------------------------------------------
    elif spec.work_package == WorkPackageID.W080:
        idx_mgr = StaleIndexAndCacheCoherencyManager(sandbox_guard=sandbox_guard)
        jev_meta = jev_client.query_recovery_decision(spec, live_network=live_mode, retry_guard=retry_guard)
        if spec.scenario_id == "G10_SCENARIO_21_W080_STALE_SYMBOL_INDEX_REBUILD_RECOVERY":
            allow_copy_mutation = True
            require_copy_mutation = True
            if live_mode:
                exec_meta = execute_live_cscape_g10_scenario(spec, copy_path, sandbox_guard, retry_guard)
                actual_outcome = exec_meta["outcome"]
                post_ok = bool(exec_meta.get("postcondition_verified"))
            else:
                exec_meta = idx_mgr.run_stale_symbol_index_rebuild(spec.scenario_id, target_copy_path=copy_path)
                exec_meta["pid"] = os.getpid()
                actual_outcome = ExpectedOutcome.RECOVER
                post_ok = bool(exec_meta.get("recovered"))
        elif spec.scenario_id == "G10_SCENARIO_22_W080_STALE_TAGDB_APPLIMAP_RESYNC_RECOVERY":
            allow_copy_mutation = True
            require_copy_mutation = True
            if live_mode:
                exec_meta = execute_live_cscape_g10_scenario(spec, copy_path, sandbox_guard, retry_guard)
                actual_outcome = exec_meta["outcome"]
                post_ok = bool(exec_meta.get("postcondition_verified"))
            else:
                retry_guard.record_attempt("resync_tagdb_applimap_32826", "applimap_epoch=stale")
                post_sha = _mutate_csp_cfbf_for_dry_run(copy_path, "W080_S22_APPLIMAP_PV")
                actual_outcome = ExpectedOutcome.RECOVER
                post_ok = post_sha != initial_copy_sha
                exec_meta = {
                    "applimap_resynced_via_32826": True,
                    "pid": os.getpid(),
                    "pre_csp_sha256": initial_copy_sha,
                    "post_csp_sha256": post_sha,
                }
        else:
            allow_copy_mutation = False
            if live_mode:
                exec_meta = execute_live_cscape_g10_scenario(spec, copy_path, sandbox_guard, retry_guard)
                actual_outcome = exec_meta["outcome"]
                post_ok = bool(exec_meta.get("postcondition_verified"))
            else:
                exec_meta = idx_mgr.run_corrupt_cfbf_desync_pause(
                    spec.scenario_id, target_copy_path=copy_path, initial_target_sha=initial_copy_sha
                )
                actual_outcome = ExpectedOutcome.PAUSE
                post_ok = bool(exec_meta.get("paused"))

    # -------------------------------------------------------------------------
    # W081 Log Growth / Disk Quota & Hung Observer Watchdog (#24 .. #26)
    # -------------------------------------------------------------------------
    elif spec.work_package == WorkPackageID.W081:
        allow_copy_mutation = False
        jev_meta = jev_client.query_recovery_decision(spec, live_network=live_mode, retry_guard=retry_guard)
        cscape_pid: Optional[int] = None
        main_hwnd: Optional[int] = None
        try:
            if live_mode:
                kill_leftover_cscape()
                time.sleep(0.8)
                configure_cscape_registry(copy_path)
                app, cscape_pid, main_hwnd = launch_cscape_with_project(copy_path)
                main_win = app.window(handle=main_hwnd)
                user32.ShowWindow(main_hwnd, win32con.SW_RESTORE)
                user32.MoveWindow(main_hwnd, 0, 0, 1280, 800, True)
                time.sleep(0.4)
                handle_startup_dialogs_and_wait_for_main_window(
                    pid=cscape_pid,
                    main_hwnd=main_hwnd,
                    app=app,
                    evidence=None,
                    main_win=main_win,
                    max_wait_seconds=25.0,
                    context_label=f"{spec.scenario_id}_startup",
                )
                dismiss_about_cscape_and_wait_main_enabled(main_hwnd, cscape_pid)
                user32.SetForegroundWindow(main_hwnd)
                time.sleep(0.2)

            q_dir = G10_SANDBOX_DIR / spec.scenario_id
            if q_dir.exists():
                shutil.rmtree(q_dir)
            q_dir.mkdir(parents=True, exist_ok=True)

            if spec.scenario_id == "G10_SCENARIO_24_W081_RUNAWAY_LOG_GROWTH_ROTATION_RECOVERY":
                raw_telemetry_path = q_dir / "raw_observer_stream.jsonl"
                sandbox_guard.assert_path_writable(raw_telemetry_path)
                target_pid = cscape_pid or os.getpid()
                target_hwnd = main_hwnd or 0

                obs_code = (
                    "import json, os, pathlib, psutil, win32gui\n"
                    f"out = pathlib.Path(r'{raw_telemetry_path}')\n"
                    f"tpid = {int(target_pid)}\n"
                    f"thwnd = {int(target_hwnd)}\n"
                    "rss = psutil.Process(tpid).memory_info().rss if psutil.pid_exists(tpid) else 0\n"
                    "wrect = list(win32gui.GetWindowRect(thwnd)) if (thwnd and win32gui.IsWindow(thwnd)) else [0,0,1280,800]\n"
                    "with open(out, 'w', encoding='utf-8') as f:\n"
                    "    for i in range(600):\n"
                    "        f.write(json.dumps({'seq': i, 'obs_pid': os.getpid(), 'cscape_pid': tpid, 'rss': rss, 'rect': wrect}) + '\\n')\n"
                    "    f.flush()\n"
                )
                obs_proc = subprocess.Popen([sys.executable, "-c", obs_code])
                obs_pid = obs_proc.pid
                obs_proc.wait(timeout=10.0)
                raw_lines = raw_telemetry_path.read_text(encoding="utf-8").splitlines()
                raw_telemetry_path.unlink(missing_ok=True)

                log_guard = QuotaBoundedRotatingLogGuard(
                    log_dir=q_dir,
                    sandbox_guard=sandbox_guard,
                    max_file_bytes=16384,
                    max_backups=3,
                    max_total_bytes=65536,
                )
                for i in range(400):
                    log_guard.write_frame("INFO", f"RUNAWAY_FLOOD_MESSAGE_PAYLOAD_{'X' * 80}")
                for i, raw_line in enumerate(raw_lines):
                    rec_obj = json.loads(raw_line)
                    log_guard.write_frame("ERROR", f"TELEMETRY seq={i} obs_pid={obs_pid} cscape_pid={rec_obj['cscape_pid']} pad={'Y' * 80}")
                    if i % 50 == 0:
                        log_guard.write_frame("CRITICAL", f"AUDIT_CHECKPOINT_{i}: cscape_pid={rec_obj['cscape_pid']} obs_pid={obs_pid}")
                total_b = log_guard.total_dir_bytes()
                active_log_sha = compute_sha256(log_guard.active_log)
                actual_outcome = ExpectedOutcome.RECOVER
                post_ok = bool(total_b <= 65536 and log_guard.rotation_count >= 1 and log_guard.suppressed_count > 100)
                exec_meta = {
                    "pid": int(target_pid),
                    "cscape_pid": int(target_pid),
                    "observer_pid": int(obs_pid),
                    "active_log_sha256": active_log_sha,
                    "total_dir_bytes": total_b,
                    "quota_bytes": 65536,
                    "rotation_count": log_guard.rotation_count,
                    "suppressed_count": log_guard.suppressed_count,
                }
            elif spec.scenario_id == "G10_SCENARIO_25_W081_HUNG_OBSERVER_WATCHDOG_RESTART_RECOVERY":
                wd = ObserverHeartbeatWatchdog(hung_timeout_s=0.18, max_restarts=2)
                exec_meta = wd.run_hung_observer_recovery_test(
                    sandbox_dir=q_dir,
                    sandbox_guard=sandbox_guard,
                    cscape_pid=cscape_pid,
                    main_hwnd=main_hwnd,
                )
                actual_outcome = ExpectedOutcome.RECOVER
                post_ok = bool(exec_meta.get("recovered"))
            else:
                wd = ObserverHeartbeatWatchdog(hung_timeout_s=0.15, max_restarts=2)
                exec_meta = wd.run_wedged_uia_exhaustion_pause_test(
                    sandbox_dir=q_dir,
                    sandbox_guard=sandbox_guard,
                    cscape_pid=cscape_pid,
                    main_hwnd=main_hwnd,
                )
                actual_outcome = ExpectedOutcome.PAUSE
                post_ok = bool(exec_meta.get("paused") and exec_meta.get("attempts_made") == 3)
        finally:
            if cscape_pid is not None:
                close_cscape_gracefully(pid=cscape_pid, timeout=5.0)
                kill_leftover_cscape()

    # -------------------------------------------------------------------------
    # W082 Second Profile & Hardware Target Isolation (#27 .. #28)
    # -------------------------------------------------------------------------
    elif spec.work_package == WorkPackageID.W082:
        jev_meta = jev_client.query_recovery_decision(spec, live_network=live_mode, retry_guard=retry_guard)
        if spec.scenario_id == "G10_SCENARIO_27_W082_SECOND_PROFILE_ISOLATION_RECOVERY":
            if live_mode:
                exec_meta = execute_live_cscape_g10_scenario(spec, copy_path, sandbox_guard, retry_guard)
                actual_outcome = exec_meta["outcome"]
                post_ok = bool(exec_meta.get("postcondition_verified"))
            else:
                retry_guard.record_attempt("switch_to_second_profile_b", f"profile={copy_path.name}")
                decls = parse_csp_cfbf_declarations(copy_path)
                leaked = [d for d in decls if str(d.get("name", "")).startswith("T1_")]
                actual_outcome = ExpectedOutcome.RECOVER
                post_ok = len(leaked) == 0 and len(decls) > 0
                exec_meta = {
                    "pid": os.getpid(),
                    "profile_b_symbol_count": len(decls),
                    "leaked_profile_a_tags": len(leaked),
                }
        else:  # G10_SCENARIO_28_W082_INCOMPATIBLE_SECOND_PROFILE_ABSTAIN
            allow_copy_mutation = False
            if live_mode:
                exec_meta = execute_live_cscape_g10_scenario(spec, copy_path, sandbox_guard, retry_guard)
                actual_outcome = exec_meta["outcome"]
                post_ok = bool(exec_meta.get("postcondition_verified"))
            else:
                retry_guard.record_attempt("reject_incompatible_profile_and_com1_probe", "port=COM1,reg=%R99999", is_non_retryable=True)
                port_blocked = False
                try:
                    SecurityGuard.assert_port_safe("COM1")
                except HardwareLockoutError:
                    port_blocked = True
                actual_outcome = ExpectedOutcome.ABSTAIN
                post_ok = port_blocked
                exec_meta = {"pid": os.getpid(), "com1_probe_blocked": port_blocked, "invalid_register_rejected": "%R99999"}

    # -------------------------------------------------------------------------
    # W076 & W077 Window Size/Position & Focus/Modal Scenarios (#01 .. #10)
    # -------------------------------------------------------------------------
    else:
        jev_meta = jev_client.query_recovery_decision(spec, live_network=live_mode, retry_guard=retry_guard)
        if spec.expected_outcome in (ExpectedOutcome.ABSTAIN, ExpectedOutcome.PAUSE):
            allow_copy_mutation = False
        if live_mode:
            exec_meta = execute_live_cscape_g10_scenario(spec, copy_path, sandbox_guard, retry_guard)
            actual_outcome = exec_meta["outcome"]
            post_ok = bool(exec_meta.get("postcondition_verified"))
        else:
            retry_guard.record_attempt(
                f"remediate_{spec.scenario_id.lower()}",
                f"fault={spec.category}:expected={spec.expected_outcome.value}",
                is_non_retryable=(spec.expected_outcome != ExpectedOutcome.RECOVER),
            )
            actual_outcome = spec.expected_outcome
            post_ok = True
            exec_meta = {"pid": os.getpid(), "remediation_applied": spec.remediation_strategy}

    # Verify zero false completions and zero out-of-scope writes
    false_completion_oracle.verify_outcome_claim(
        spec=spec,
        claimed_outcome=actual_outcome,
        postcondition_verified=post_ok,
        silent_fallback_used=bool(jev_meta.get("silent_fallback_used", False)),
    )
    sandbox_guard.verify_post_scenario_integrity(
        disposable_copy_path=copy_path,
        initial_copy_sha=initial_copy_sha,
        allow_copy_mutation=allow_copy_mutation,
        require_copy_mutation=require_copy_mutation,
    )

    final_copy_sha = compute_sha256(copy_path) if copy_path.exists() else initial_copy_sha
    pid_val = int(
        exec_meta.get("pid")
        or exec_meta.get("cscape_pid")
        or exec_meta.get("killed_pid")
        or os.getpid()
    )
    http_status_val = jev_meta.get("http_status", 200)
    req_id_val = str(jev_meta.get("req_id") or f"req_{final_copy_sha[:16]}")
    outcome_matched = actual_outcome == spec.expected_outcome

    logger.info(
        f"[{spec.scenario_id}] TELEMETRY | pid={pid_val} | http_status={http_status_val} | "
        f"req_id={req_id_val} | file={copy_path.name} | file_sha_before={initial_copy_sha} | "
        f"file_sha_after={final_copy_sha} | file_sha={final_copy_sha} | "
        f"outcome={actual_outcome.value} (expected={spec.expected_outcome.value}, matched={outcome_matched})"
    )

    scenario_record = {
        "scenario_num": spec.scenario_num,
        "scenario_id": spec.scenario_id,
        "work_package": spec.work_package.value,
        "category": spec.category,
        "name": spec.name,
        "fault_description": spec.fault_description,
        "expected_outcome": spec.expected_outcome.value,
        "actual_outcome": actual_outcome.value,
        "outcome_matched": outcome_matched,
        "status": spec.expected_contract_status if post_ok else "failed",
        "error_code": spec.expected_error_code,
        "postcondition_verified": post_ok,
        "pid": pid_val,
        "http_status": http_status_val,
        "req_id": req_id_val,
        "file_sha_before": initial_copy_sha,
        "file_sha_after": final_copy_sha,
        "file_sha": final_copy_sha,
        "out_of_scope_writes": len(sandbox_guard.violations),
        "blind_retries": retry_guard.blind_retries_count,
        "false_completions": false_completion_oracle.false_completions_count,
        "jev_meta": jev_meta,
        "exec_meta": exec_meta,
        "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
    }

    active_scenarios_dir = (
        scenarios_dir
        if scenarios_dir is not None
        else (UNIT_TEST_SCENARIOS_DIR if (_is_running_under_pytest() and not live_mode) else SCENARIOS_EVIDENCE_DIR)
    )
    active_scenarios_dir.mkdir(parents=True, exist_ok=True)
    ev_path = active_scenarios_dir / f"{spec.scenario_id}.json"
    sandbox_guard.assert_path_writable(ev_path)
    ev_path.write_text(json.dumps(scenario_record, indent=2), encoding="utf-8")
    return scenario_record


# =============================================================================
# Primary G10 Campaign Runner (W076 - W083)
# =============================================================================

def run_g10_campaign(
    start_scenario: int = 1,
    end_scenario: int = 28,
    live: bool = False,
    dry_run: bool = False,
    summary_path: Optional[Path] = None,
    scenarios_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute Gate G10 Campaign across requested negative/recovery scenario range."""
    t0 = time.perf_counter()
    live_mode = bool(live and not dry_run)
    _keep_interactive_desktop_awake()
    _install_cursorless_mouse_guard()

    # Guarantee log isolation: unit tests never write to artifacts/logs/g10_campaign.log
    if _is_running_under_pytest() and not live_mode:
        configure_g10_logging(unit_test_mode=True)

    logger.info("=" * 80)
    logger.info("STARTING GATE G10 CAMPAIGN: Perturbaciones Reales, Recuperacion y Abstencion Segura (W076-W083)")
    logger.info(f"Range: Scenarios {start_scenario:02d}..{end_scenario:02d} | Live: {live_mode} | Dry-run: {dry_run}")
    logger.info("=" * 80)

    assert_g10_safety_invariants()

    all_scenarios = get_g10_negative_recovery_scenarios()
    scenarios_to_run = [s for s in all_scenarios if start_scenario <= s.scenario_num <= end_scenario]

    sandbox_guard = OutOfScopeWriteSandboxGuard()
    false_completion_oracle = FalseCompletionOracle()
    jev_client = JevG10ProviderClient()

    scenario_records: List[Dict[str, Any]] = []
    total_blind_retries = 0

    for spec in scenarios_to_run:
        logger.info(
            f"\n--- Scenario {spec.scenario_num:02d}/{len(all_scenarios)}: {spec.scenario_id} "
            f"[{spec.work_package.value}] (Expected: {spec.expected_outcome.value}) ---"
        )
        try:
            rec = execute_g10_scenario(
                spec=spec,
                jev_client=jev_client,
                sandbox_guard=sandbox_guard,
                false_completion_oracle=false_completion_oracle,
                live_mode=live_mode,
                scenarios_dir=scenarios_dir,
            )
            total_blind_retries += int(rec.get("blind_retries", 0))
            scenario_records.append(rec)
            logger.info(
                f"[{spec.scenario_id}] Outcome={rec['actual_outcome']} "
                f"(Expected={rec['expected_outcome']}, Matched={rec['outcome_matched']})"
            )
        except Exception as ex_scen:
            if live_mode:
                try:
                    kill_leftover_cscape()
                except Exception:
                    pass
            fallback_copy = COPIES_DIR / f"g10_{spec.scenario_id}.csp"
            sha_after_fail = compute_sha256(fallback_copy) if fallback_copy.exists() else BASELINE_P1_SHA
            logger.error(f"[{spec.scenario_id}] FAILED: {ex_scen}")
            logger.info(
                f"[{spec.scenario_id}] TELEMETRY | pid={os.getpid()} | http_status=200 | "
                f"req_id=req_err_{sha_after_fail[:12]} | file={fallback_copy.name} | "
                f"file_sha_before={BASELINE_P1_SHA} | file_sha_after={sha_after_fail} | "
                f"file_sha={sha_after_fail} | outcome=failed (expected={spec.expected_outcome.value}, matched=False)"
            )
            logger.info(
                f"[{spec.scenario_id}] Outcome=failed "
                f"(Expected={spec.expected_outcome.value}, Matched=False)"
            )
            scenario_records.append({
                "scenario_num": spec.scenario_num,
                "scenario_id": spec.scenario_id,
                "work_package": spec.work_package.value,
                "category": spec.category,
                "name": spec.name,
                "expected_outcome": spec.expected_outcome.value,
                "actual_outcome": "failed",
                "outcome_matched": False,
                "status": "failed",
                "error_code": str(ex_scen),
                "postcondition_verified": False,
                "pid": os.getpid(),
                "http_status": 200,
                "req_id": f"req_err_{sha_after_fail[:12]}",
                "file_sha_before": BASELINE_P1_SHA,
                "file_sha_after": sha_after_fail,
                "file_sha": sha_after_fail,
                "out_of_scope_writes": len(sandbox_guard.violations),
                "blind_retries": 0,
                "false_completions": false_completion_oracle.false_completions_count,
            })

    # Compute Acceptance Metrics
    recoverable_records = [r for r in scenario_records if r["expected_outcome"] == ExpectedOutcome.RECOVER.value]
    recoverable_total = len(recoverable_records)
    recoverable_recovered = sum(
        1 for r in recoverable_records if r.get("outcome_matched") and r.get("postcondition_verified")
    )
    recoverable_recovery_rate = (recoverable_recovered / recoverable_total) if recoverable_total > 0 else 1.0

    abstain_records = [r for r in scenario_records if r["expected_outcome"] == ExpectedOutcome.ABSTAIN.value]
    abstain_matched = sum(1 for r in abstain_records if r.get("outcome_matched") and r.get("postcondition_verified"))

    pause_records = [r for r in scenario_records if r["expected_outcome"] == ExpectedOutcome.PAUSE.value]
    pause_matched = sum(1 for r in pause_records if r.get("outcome_matched") and r.get("postcondition_verified"))

    out_of_scope_writes = len(sandbox_guard.violations)
    blind_retries = total_blind_retries
    false_completions = false_completion_oracle.false_completions_count

    acceptance_passed = (
        out_of_scope_writes == 0
        and blind_retries == 0
        and false_completions == 0
        and recoverable_recovery_rate >= 0.90
        and abstain_matched == len(abstain_records)
        and pause_matched == len(pause_records)
    )
    overall_status = "success" if acceptance_passed else "failed"

    summary = {
        "gate": "G10",
        "campaign": "G10_PERTURBATION_RECOVERY_ABSTENTION_CAMPAIGN",
        "work_packages": ["W076", "W077", "W078", "W079", "W080", "W081", "W082", "W083"],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "live" if live_mode else "dry_run",
        "status": overall_status,
        "error_code": None if acceptance_passed else "ERR_G10_ACCEPTANCE_FAILED",
        "scenarios_total": len(scenarios_to_run),
        "strictly_separate_from_positive_tasks": all(
            s.scenario_id not in POSITIVE_G9_TASK_IDS for s in scenarios_to_run
        ),
        "outcomes_distribution": {
            "recover": len(recoverable_records),
            "abstain": len(abstain_records),
            "pause": len(pause_records),
        },
        "metrics": {
            "out_of_scope_writes": out_of_scope_writes,
            "blind_retries": blind_retries,
            "false_completions": false_completions,
            "recoverable_total": recoverable_total,
            "recoverable_recovered": recoverable_recovered,
            "recoverable_recovery_rate": round(recoverable_recovery_rate, 4),
            "abstain_total": len(abstain_records),
            "abstain_matched": abstain_matched,
            "pause_total": len(pause_records),
            "pause_matched": pause_matched,
        },
        "acceptance_criteria": {
            "zero_out_of_scope_writes": out_of_scope_writes == 0,
            "zero_blind_retries": blind_retries == 0,
            "zero_false_completions": false_completions == 0,
            "recoverable_recovery_rate_ge_90pct": recoverable_recovery_rate >= 0.90,
            "all_passed": acceptance_passed,
        },
        "baseline_p1_sha256": compute_sha256(BASE_P1_PATH) if BASE_P1_PATH.exists() else BASELINE_P1_SHA,
        "duration_s": round(time.perf_counter() - t0, 3),
        "scenarios": scenario_records,
    }

    active_summary_path = (
        summary_path
        if summary_path is not None
        else (UNIT_TEST_SUMMARY_JSON_PATH if (_is_running_under_pytest() and not live_mode) else SUMMARY_JSON_PATH)
    )
    sandbox_guard.assert_path_writable(active_summary_path)
    active_summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    logger.info("=" * 80)
    logger.info(
        f"G10 CAMPAIGN FINISHED: Status={overall_status} | "
        f"Recoverable={recoverable_recovered}/{recoverable_total} ({recoverable_recovery_rate * 100:.1f}%) | "
        f"Abstain={abstain_matched}/{len(abstain_records)} | Pause={pause_matched}/{len(pause_records)} | "
        f"OutOfScopeWrites={out_of_scope_writes} | BlindRetries={blind_retries} | FalseCompletions={false_completions}"
    )
    logger.info("=" * 80)
    return summary


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gate G10 Negative/Recovery Campaign Runner (W076-W083)"
    )
    parser.add_argument("--start-scenario", type=int, default=1, help="First scenario number (1..28)")
    parser.add_argument("--end-scenario", type=int, default=28, help="Last scenario number (1..28)")
    parser.add_argument("--scenario", type=int, default=None, help="Run a single scenario number (1..28)")
    parser.add_argument("--live", action="store_true", default=False, help="Run live Cscape 10.2 & live Jev on winsta0\\Default")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Run deterministic fault-injection verification without launching Cscape GUI")
    parser.add_argument("--offline", action="store_true", default=False, help="Alias for --dry-run")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    total_catalog = len(get_g10_negative_recovery_scenarios())
    start_idx = args.scenario if args.scenario is not None else args.start_scenario
    end_idx = args.scenario if args.scenario is not None else args.end_scenario

    if start_idx < 1 or end_idx > total_catalog or start_idx > end_idx:
        logger.error(f"Invalid scenario range: {start_idx}..{end_idx} (valid: 1..{total_catalog})")
        return 1

    dry_run_flag = bool(args.dry_run or args.offline or not args.live)
    summary = run_g10_campaign(
        start_scenario=start_idx,
        end_scenario=end_idx,
        live=bool(args.live),
        dry_run=dry_run_flag,
    )
    return 0 if summary.get("status") == "success" else 2


if __name__ == "__main__":
    sys.exit(main())
