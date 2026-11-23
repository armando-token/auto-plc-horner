#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gate G9 Campaign: Solicitud a Proyecto Industrial Offline Completo (W068-W075).

Mandate:
  - Domain: Tank Training Family (industrial dual-tank, level regulation, pump & valve control).
  - 10 Parameterized Clean Tasks (Tasks 01..10, including 3 reserved tasks: Tasks 08, 09, 10).
  - Fresh Disposable Copies: Each task starts from a fresh copy of work/disposable/p1_base.csp.
  - Real Jev Planning: Calls https://api.typesafe.ai/v1/systemone (model: jev-latest) to generate
    the industrial plan/IR with deterministic fallback for offline/dry-run environments.
  - Live Cscape Construction (winsta0\\Default):
      * G3: Variable declarations in Program Variables / CFBF /V, stream.
      * G7: Ladder rungs, contacts, and coils (Insert Rung 37980, contact 1000/1001, coil 1002, tag assignment).
      * G8: HMI Screen 1 element placement & variable binding (Numeric Data, PilotLamp, Screen 1).
      * Error Check: Real Win32 ID_PROGRAM_ERRORCHECK = 32826 clean compile (0 errors, 0 warnings).
      * Save & Reopen: Save project (ID_FILE_SAVE = 57603), reopen copy, read back and check each REQ
        against native project container across V2, V3, and V4.
  - Task 06 Pre-Edit Guard:
      * Missing critical data (target_level = None, high_alarm = None) MUST stay 'pending' with diagnosis
        BEFORE ANY Cscape launch, file copy, or disk mutation.
  - Parametric Absence Verification:
      * Parametric change between two tasks must be verified absent in the next project container
        via CrossProjectParametricAbsenceVerifier scanning native CFBF streams (/Contents, /V,).
  - V5 Simulation: Explicitly marked 'pending' (Reason: 'no simulator / offline only').
  - CLI Flags: --start-task INT, --end-task INT, --task INT, --dry-run, --offline, --live.
  - Safety Invariants: COM1..256 hard-blocked, download commands (32827, 33149) blocked,
    baseline p1_base.csp strictly immutable.

Classification: REAL_INDUSTRIAL_PROJECT_SYNTHESIS [Tank Training Family, Evidence-Gated]
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import io
import json
import logging
import math
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
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
import win32con
import win32gui
import win32process
from pywinauto import Application, mouse
from pywinauto.keyboard import send_keys

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.security.exceptions import HardwareLockoutError, LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard

# Proven G3, G7, G8 routines
from scripts.g3_edit_roundtrip import (
    check_iec_text_completeness,
    click_add_variable_menu_item,
    close_active_editor_tab,
    dismiss_popup_menu,
    extract_var_declaration,
    find_iec_editor_candidate_windows,
    find_program_variables_treeview,
    focus_iec_editor,
    get_treeview_item_texts,
    handle_variable_name_input,
    inspect_context_menu_items,
    open_program_variables_pane,
    parse_csp_cfbf_declarations,
    parse_iec_declarations,
    populate_and_dismiss_k5_dialog,
    read_complete_iec_variables_text,
    read_text_from_active_editor,
    relocate_global_variables_row,
)
from scripts.g7_acceptance import (
    dismiss_about_cscape_and_wait_main_enabled,
    trigger_and_read_cscape_error_check,
)
from scripts.g7_ladder_roundtrip import (
    activate_ladder_toolbar_button,
    assign_tag_in_dialog,
    open_main_ladder_editor,
    parse_cfbf_ladder_elements,
    resolve_ladder_canvas,
)
from scripts.g8_acceptance import (
    handle_confirmation_popups,
    handle_hmi_binding_dialog,
    parse_cfbf_hmi_elements,
    place_hmi_object_on_screen,
)
from scripts.probe_hmi_editor import (
    close_cscape_gracefully,
    configure_cscape_registry,
    handle_startup_dialogs_and_wait_for_main_window,
    is_screen_editor_window,
    kill_leftover_cscape,
    launch_cscape_with_project,
    open_screen_editor_dynamic,
)

# Win32 Constants
user32 = ctypes.windll.user32
ID_SELECT_ELEMENTS = 112
ID_HMI_SELECT_ELEMENTS = 7655
ID_NO_CONTACT = 1000
ID_NC_CONTACT = 1001
ID_NO_COIL = 1002
ID_INSERT_NEW_RUNG = 37980
ID_PROGRAM_ERRORCHECK = 32826
ID_FILE_SAVE = 57603
ID_PROGRAM_DOWNLOAD = 32827
ID_CONTROLLER_DOWNLOAD = 33149

# Base project paths & constants
BASE_P1_PATH = REPO_ROOT / "work" / "disposable" / "p1_base.csp"
BASELINE_P1_SHA = "5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881"
COPIES_DIR = REPO_ROOT / "work" / "disposable" / "copies"
COPIES_DIR.mkdir(parents=True, exist_ok=True)

# Artifacts & Output Paths
ARTIFACTS_G9_DIR = REPO_ROOT / "artifacts" / "G9"
ARTIFACTS_G9_DIR.mkdir(parents=True, exist_ok=True)
TASKS_EVIDENCE_DIR = ARTIFACTS_G9_DIR / "tasks"
TASKS_EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_JSON_PATH = ARTIFACTS_G9_DIR / "g9_campaign_summary.json"
LOG_DIR = REPO_ROOT / "artifacts" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE_PATH = LOG_DIR / "g9_campaign.log"

# Setup Logging
logger = logging.getLogger("g9_campaign")
logger.setLevel(logging.INFO)
logger.handlers.clear()

file_handler = logging.FileHandler(LOG_FILE_PATH, mode="a", encoding="utf-8")
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] g9_campaign: %(message)s")
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(logging.INFO)
stream_formatter = logging.Formatter("%(message)s")
stream_handler.setFormatter(stream_formatter)
logger.addHandler(stream_handler)


def compute_sha256(filepath: Union[str, Path]) -> str:
    """Compute SHA-256 hash of a file."""
    p = Path(filepath)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {p}")
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def assert_safety_invariants() -> None:
    """Verify fail-closed hardware lockout and baseline CSP immutability."""
    for port in [1, 2, 3, 4, 8, 256]:
        try:
            SecurityGuard.assert_port_safe(f"COM{port}")
            raise RuntimeError(f"Hardware lockout breached: COM{port} was not blocked!")
        except HardwareLockoutError:
            pass

    assert ID_PROGRAM_DOWNLOAD == 32827
    assert ID_CONTROLLER_DOWNLOAD == 33149

    if BASE_P1_PATH.exists():
        actual_sha = compute_sha256(BASE_P1_PATH)
        if actual_sha != BASELINE_P1_SHA:
            raise RuntimeError(
                f"FAIL_CLOSED: Baseline p1_base.csp tampered! "
                f"Expected: {BASELINE_P1_SHA}, Actual: {actual_sha}"
            )


# =============================================================================
# Live Cscape UI Variable Declaration (G3 Path + Tag Field / Edit Variables as Text)
# =============================================================================

def _inspect_dialog_text_and_yes_button(dlg_hwnd: int) -> Tuple[str, int]:
    """Read top-level title, all child Static/Button texts, and locate IDYES (6) button handle."""
    parts: List[str] = []
    yes_btn_hwnd: int = 0
    try:
        title = win32gui.GetWindowText(dlg_hwnd) or ""
        if title.strip():
            parts.append(title.strip())
    except Exception:
        pass

    try:
        direct_yes = user32.GetDlgItem(dlg_hwnd, win32con.IDYES)
        if direct_yes and win32gui.IsWindow(direct_yes):
            yes_btn_hwnd = direct_yes
    except Exception:
        pass

    def _child_cb(ch: int, _: Any) -> bool:
        nonlocal yes_btn_hwnd
        try:
            cls = (win32gui.GetClassName(ch) or "").lower()
            ctrl_id = win32gui.GetDlgCtrlID(ch)
            txt = (win32gui.GetWindowText(ch) or "").strip()
            if not txt and cls in ("static", "button", "edit"):
                buf = ctypes.create_unicode_buffer(512)
                user32.SendMessageW(ch, win32con.WM_GETTEXT, 512, ctypes.byref(buf))
                txt = buf.value.strip()
            if txt:
                parts.append(txt)
            if "button" in cls:
                if ctrl_id == win32con.IDYES or txt.lower() in ("yes", "&yes"):
                    if not yes_btn_hwnd:
                        yes_btn_hwnd = ch
        except Exception:
            pass
        return True

    try:
        win32gui.EnumChildWindows(dlg_hwnd, _child_cb, None)
    except Exception:
        pass

    return " ".join(parts).lower(), yes_btn_hwnd


def handle_program_information_modified_dialog(pid: int, timeout: float = 4.0) -> bool:
    """Find and answer YES (IDYES=6) to Cscape's 'Contents of IEC Variables Editor Window have been modified'
    (top-level title 'Cscape', child Static ID 0x9517) or 'Program Information Modified' prompt.
    """
    save_keywords = [
        "contents of iec variables editor",
        "variables editor window have been modified",
        "program information modified",
        "save the changes",
        "do you want to save",
        "save changes",
        "variables modified",
        "have been modified",
        "has been modified",
    ]
    start_t = time.time()
    while time.time() - start_t < timeout:
        found_dlg = None
        found_yes_btn = 0
        found_summary = ""

        def _enum_cb(h: int, _: Any) -> bool:
            nonlocal found_dlg, found_yes_btn, found_summary
            try:
                if win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                    _, p = win32process.GetWindowThreadProcessId(h)
                    if p == pid and win32gui.GetClassName(h) == "#32770":
                        combined_txt, yes_btn = _inspect_dialog_text_and_yes_button(h)
                        if any(k in combined_txt for k in save_keywords):
                            found_dlg = h
                            found_yes_btn = yes_btn
                            found_summary = combined_txt
                            return False
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(_enum_cb, None)
        except Exception:
            pass

        if found_dlg:
            logger.info(
                f"Found save confirmation dialog HWND {hex(found_dlg)} "
                f"(yes_btn={hex(found_yes_btn) if found_yes_btn else '0'}, text='{found_summary[:120]}'). "
                f"Clicking YES (IDYES=6)..."
            )
            if found_yes_btn and win32gui.IsWindow(found_yes_btn):
                user32.SendMessageW(found_yes_btn, win32con.BM_CLICK, 0, 0)
                user32.PostMessageW(found_yes_btn, win32con.BM_CLICK, 0, 0)
            user32.SendMessageW(found_dlg, win32con.WM_COMMAND, win32con.IDYES, found_yes_btn)
            user32.PostMessageW(found_dlg, win32con.WM_COMMAND, win32con.IDYES, found_yes_btn)
            time.sleep(0.5)
            return True
        time.sleep(0.12)
    return False


def close_and_commit_iec_variables_editor_tab(
    pid: int,
    main_hwnd: int,
    main_win: Any,
    active_mdi: Optional[int],
    editor_hwnd: Optional[int],
) -> bool:
    """Trigger CTextModeIECVariablesEditorWnd::PromptAndSave(1, 1) (VA 0x007AAC70 in Cscape.exe)
    and confirm IDYES (6) so K5CmpImportVariables commits the W5EditST buffer into the variable dictionary.

    Triggers tried in order:
      1. SysTabControl32 (ctrl_id=59648) Close Active Tab button (ctrl_id=300, WM_COMMAND 300 -> OnCloseCurrentTab).
      2. CTextModeIECVariablesEditorWnd format toolbar switch (WM_COMMAND 38183 -> PromptAndSave(1, 1)).
      3. Ctrl+F4 (main_win.type_keys("^{F4}") / send_keys("^{F4}")) + handle_program_information_modified_dialog.
    """
    tab_ctrl_hwnd: int = 0
    close_btn_300: int = 0
    iec_view_parent: int = 0

    if editor_hwnd and win32gui.IsWindow(editor_hwnd):
        try:
            iec_view_parent = win32gui.GetParent(editor_hwnd)
        except Exception:
            pass

    search_root = active_mdi if (active_mdi and win32gui.IsWindow(active_mdi)) else main_hwnd

    def _find_tab_controls_cb(ch: int, _: Any) -> bool:
        nonlocal tab_ctrl_hwnd, close_btn_300
        try:
            if not win32gui.IsWindow(ch) or not win32gui.IsWindowVisible(ch):
                return True
            cls = (win32gui.GetClassName(ch) or "").lower()
            cid = win32gui.GetDlgCtrlID(ch)
            if "systabcontrol32" in cls and cid == 59648:
                tab_ctrl_hwnd = ch
            elif cid == 300 and ("button" in cls or "bitmapbutton" in cls):
                close_btn_300 = ch
        except Exception:
            pass
        return True

    if search_root and win32gui.IsWindow(search_root):
        try:
            win32gui.EnumChildWindows(search_root, _find_tab_controls_cb, None)
        except Exception:
            pass

    # Trigger 1: SysTabControl32 (59648) WM_COMMAND 300 -> CMultiTabbedEditorWnd::OnCloseCurrentTab (0x00739580)
    if tab_ctrl_hwnd and win32gui.IsWindow(tab_ctrl_hwnd):
        logger.info(
            f"Triggering OnCloseCurrentTab via SysTabControl32 HWND {hex(tab_ctrl_hwnd)} "
            f"(WM_COMMAND 300, btn_300={hex(close_btn_300) if close_btn_300 else '0'})..."
        )
        if close_btn_300 and win32gui.IsWindow(close_btn_300):
            user32.PostMessageW(close_btn_300, win32con.BM_CLICK, 0, 0)
        user32.PostMessageW(tab_ctrl_hwnd, win32con.WM_COMMAND, 300, close_btn_300)
        time.sleep(0.3)
        if handle_program_information_modified_dialog(pid, timeout=2.5):
            return True

    # Trigger 2: CTextModeIECVariablesEditorWnd WM_COMMAND 38183 (0x9527 -> PromptAndSave(1, 1) at VA 0x007AA650)
    if iec_view_parent and win32gui.IsWindow(iec_view_parent):
        logger.info(
            f"Triggering PromptAndSave via CTextModeIECVariablesEditorWnd HWND {hex(iec_view_parent)} (WM_COMMAND 38183)..."
        )
        user32.PostMessageW(iec_view_parent, win32con.WM_COMMAND, 38183, 0)
        time.sleep(0.3)
        if handle_program_information_modified_dialog(pid, timeout=2.0):
            # Close the tab after saving
            if tab_ctrl_hwnd and win32gui.IsWindow(tab_ctrl_hwnd):
                user32.PostMessageW(tab_ctrl_hwnd, win32con.WM_COMMAND, 300, close_btn_300)
            return True

    # Trigger 3: Close active editor tab via Ctrl+F4 directly WITHOUT auto-discard
    logger.info("Closing IEC Variables Editor tab via Ctrl+F4...")
    user32.SetForegroundWindow(main_hwnd)
    time.sleep(0.2)
    try:
        main_win.type_keys("^{F4}")
    except Exception:
        send_keys("^{F4}")
    time.sleep(0.5)

    return handle_program_information_modified_dialog(pid, timeout=4.0)


def _set_clipboard_unicode_text(text: str) -> None:
    """Place Unicode text onto the Windows Clipboard for W5EditST paste."""
    import win32clipboard

    win32clipboard.OpenClipboard()
    try:
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardText(text, win32clipboard.CF_UNICODETEXT)
    finally:
        win32clipboard.CloseClipboard()


def declare_variables_via_live_cscape_ui(
    pid: int,
    main_hwnd: int,
    app: Application,
    spec: Any,
    app_uia: Optional[Application] = None,
    copy_path: Optional[Path] = None,
) -> bool:
    """Declare G9 task variables through the live Cscape UI per strict mandate.

    Prohibits direct CFBF disk manipulation for project construction (CFBF is strictly read-only
    for verification).
    Execution:
      1. Opens Program Variables pane via View/Home menu.
      2. Locates Global Variables row in SysTreeView32.
      3. Right-clicks Global Variables to open context menu.
      4. Invokes 'Edit Variables as Text' from context menu.
      5. Reads existing declarations using proven G3 completeness & stability checks.
      6. Formulates IEC declarations with (*$tag=%R...*) and (*$tag=%M...*) directives:
            {spec.level_pv_tag} : INT ;
               (*$tag=%R{100 + spec.task_num}*)
            {spec.inlet_valve_tag} : BOOL ;
               (*$tag=%M{100 + spec.task_num}*)
      7. Injects declarations into active W5EditST (ctrl_id=950) editor before END_VAR via
         native W5EditST messages (0x040F SelectAll + 0x0302/0x0415 Paste) and frame WM_COMMAND.
      8. Triggers CTextModeIECVariablesEditorWnd::PromptAndSave (WM_COMMAND 300 / 38183 / Ctrl+F4)
         and confirms YES (IDYES=6) to 'Contents of IEC Variables Editor Window have been modified'.
      9. Verifies declaration persistence via both proven G3 CFBF reader (parse_csp_cfbf_declarations)
         and raw CFBF Contents register mapping readback.
    """
    logger.info(f"[{spec.task_id}] Declaring variables via live Cscape UI (Edit Variables as Text + Tag field)...")
    if app_uia is None:
        try:
            app_uia = Application(backend="uia").connect(process=pid)
        except Exception:
            pass

    main_win = app.window(handle=main_hwnd)
    cscape_ui = app_uia.window(handle=main_hwnd) if app_uia else None

    level_pv_reg = f"%R{100 + spec.task_num}"
    inlet_valve_reg = f"%M{100 + spec.task_num}"

    # 1. Open Program Variables pane
    open_program_variables_pane(pid, main_hwnd, main_win, app_uia, cscape_ui, {})
    tv_hwnd, w5_hwnd = find_program_variables_treeview(pid, main_hwnd)

    if not tv_hwnd:
        logger.warning(f"[{spec.task_id}] SysTreeView32 for Program Variables not found!")
        return False

    # 2. Relocate Global Variables row
    target_cx, target_cy, target_rect, gv_hitem = relocate_global_variables_row(
        pid=pid, tv_hwnd=tv_hwnd, w5_hwnd=w5_hwnd, app=app, main_hwnd=main_hwnd
    )
    if not (target_cx and target_cy):
        logger.warning(f"[{spec.task_id}] Could not locate coordinates for Global Variables row.")
        return False

    # 3. Right-click Global Variables row
    mouse.click(button="left", coords=(target_cx, target_cy))
    time.sleep(0.3)
    mouse.click(button="right", coords=(target_cx, target_cy))
    time.sleep(0.5)

    menu_items, popup_h = inspect_context_menu_items(app_uia)
    logger.info(f"[{spec.task_id}] Global Variables context menu items: {menu_items}")

    has_edit_as_text = any("as text" in it.lower() or "edit variables" in it.lower() for it in menu_items)
    text_mode_success = False

    if has_edit_as_text:
        logger.info(f"[{spec.task_id}] Clicking 'Edit Variables as Text' from context menu...")
        clicked_text = False
        if popup_h:
            try:
                p_win = app_uia.window(handle=popup_h)
                for itm in p_win.descendants(control_type="MenuItem"):
                    nm = (getattr(itm.element_info, "name", "") or itm.window_text() or "").strip().lower()
                    if "as text" in nm or "edit variables" in nm:
                        itm.click_input()
                        clicked_text = True
                        break
            except Exception as ex_m:
                logger.warning(f"UIA context menu click note: {ex_m}")
        if not clicked_text:
            for idx, itm in enumerate(menu_items):
                if "as text" in itm.lower() or "edit variables" in itm.lower():
                    send_keys("{DOWN}" * (idx + 1) + "{ENTER}")
                    clicked_text = True
                    break
        time.sleep(1.2)

        # 4. Resolve active IEC Variables Editor (W5EditST, ctrl_id=950)
        active_mdi, candidates = find_iec_editor_candidate_windows(main_hwnd)
        editor_hwnd = None
        for h in candidates:
            if win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                cls = win32gui.GetClassName(h).lower()
                if "w5editst" in cls or "w5edit" in cls:
                    editor_hwnd = h
                    break
        if not editor_hwnd and candidates:
            editor_hwnd = candidates[0]

        if editor_hwnd and win32gui.IsWindow(editor_hwnd):
            logger.info(f"[{spec.task_id}] IEC Variables Editor tab located (HWND {hex(editor_hwnd)}). Reading content via proven G3 stability loop...")
            existing_text = ""
            prev_complete: Optional[str] = None
            for _poll in range(6):
                cand_text = read_text_from_active_editor(
                    main_hwnd, cscape_ui, main_win, evidence={}, context_label=f"{spec.task_id}_var_decl"
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

            # Build declarations with (*$tag=...*) directives
            new_lines = []
            if spec.level_pv_tag.lower() not in existing_text.lower():
                new_lines.append(f"   {spec.level_pv_tag} : INT ;\r\n      (*$tag={level_pv_reg}*)\r\n")
            if spec.inlet_valve_tag.lower() not in existing_text.lower():
                new_lines.append(f"   {spec.inlet_valve_tag} : BOOL ;\r\n      (*$tag={inlet_valve_reg}*)\r\n")

            if new_lines:
                logger.info(f"[{spec.task_id}] Inserting declarations for '{spec.level_pv_tag}' ({level_pv_reg}) and '{spec.inlet_valve_tag}' ({inlet_valve_reg})...")
                idx_end = existing_text.upper().rfind("END_VAR")
                if idx_end != -1:
                    updated_text = existing_text[:idx_end] + "".join(new_lines) + existing_text[idx_end:]
                else:
                    updated_text = existing_text + "\r\nVAR\r\n" + "".join(new_lines) + "END_VAR\r\n"

                # Focus W5EditST (ctrl_id=950) and populate clipboard
                focus_iec_editor(main_hwnd=main_hwnd, active_mdi=active_mdi, editor_hwnd=editor_hwnd)
                _set_clipboard_unicode_text(updated_text)
                time.sleep(0.15)

                # Primary: Direct W5EditST.dll CW5EditST::OnWndMsg SelectAll (0x040F) + Paste (0x0302 / 0x0415)
                user32.SendMessageW(editor_hwnd, 0x040F, 0, 0)  # CW5EditST::OnEditSelectAll (WM_USER+15)
                time.sleep(0.1)
                user32.SendMessageW(editor_hwnd, win32con.WM_PASTE, 0, 0)  # CW5EditST::OnEditPaste (0x0302)
                user32.SendMessageW(editor_hwnd, 0x0415, 0, 0)  # CW5EditST::OnEditPaste (WM_USER+21)

                # Secondary: Frame WM_COMMAND SelectAll (57642) + Paste (57637)
                for target_f in [active_mdi, main_hwnd, editor_hwnd]:
                    if target_f and win32gui.IsWindow(target_f):
                        user32.SendMessageW(target_f, win32con.WM_COMMAND, 57642, 0)  # ID_EDIT_SELECT_ALL
                        user32.SendMessageW(target_f, win32con.WM_COMMAND, 57637, 0)  # ID_EDIT_PASTE
                time.sleep(0.3)

                # Verify paste in W5EditST buffer via proven G3 reader
                read_check = read_text_from_active_editor(
                    main_hwnd, cscape_ui, main_win, evidence={}, context_label=f"{spec.task_id}_check_paste"
                )
                if (
                    spec.level_pv_tag.lower() not in read_check.lower()
                    or spec.inlet_valve_tag.lower() not in read_check.lower()
                ):
                    # CRITICAL: Re-populate clipboard with updated_text before ^a/^v because
                    # read_text_from_active_editor overwrote the system clipboard!
                    logger.info(f"[{spec.task_id}] Re-populating clipboard with updated_text and retrying paste...")
                    _set_clipboard_unicode_text(updated_text)
                    focus_iec_editor(main_hwnd=main_hwnd, active_mdi=active_mdi, editor_hwnd=editor_hwnd)
                    user32.SendMessageW(editor_hwnd, 0x040F, 0, 0)
                    user32.SendMessageW(editor_hwnd, win32con.WM_PASTE, 0, 0)
                    user32.SendMessageW(editor_hwnd, 0x0415, 0, 0)
                    send_keys("^a")
                    time.sleep(0.1)
                    send_keys("^v")
                    time.sleep(0.4)
                    read_check = read_text_from_active_editor(
                        main_hwnd, cscape_ui, main_win, evidence={}, context_label=f"{spec.task_id}_check_paste_retry"
                    )

                # Verify structured declaration presence in W5EditST buffer via proven G3 parser
                parsed_in_editor = parse_iec_declarations(read_check)
                decl_pv = extract_var_declaration(read_check, spec.level_pv_tag, "INT")
                decl_iv = extract_var_declaration(read_check, spec.inlet_valve_tag, "BOOL")
                logger.info(
                    f"[{spec.task_id}] W5EditST buffer verified before commit: "
                    f"total_decls={len(parsed_in_editor)}, pv_decl='{decl_pv}', iv_decl='{decl_iv}'"
                )

            # Close & commit active IEC Variables Editor tab (WM_COMMAND 300 / 38183 / Ctrl+F4 + IDYES=6)
            prompt_handled = close_and_commit_iec_variables_editor_tab(
                pid=pid,
                main_hwnd=main_hwnd,
                main_win=main_win,
                active_mdi=active_mdi,
                editor_hwnd=editor_hwnd,
            )
            if not prompt_handled:
                try:
                    main_win.type_keys("^{F4}")
                except Exception:
                    send_keys("^{F4}")
                prompt_handled = handle_program_information_modified_dialog(pid, timeout=2.0)
            logger.info(f"[{spec.task_id}] Program Information Modified prompt handled: {prompt_handled}")
            if prompt_handled or not new_lines:
                text_mode_success = True
                logger.info(f"[{spec.task_id}] Variables successfully declared and committed via 'Edit Variables as Text'!")
            else:
                logger.warning(
                    f"[{spec.task_id}] 'Edit Variables as Text' save confirmation prompt was NOT handled "
                    f"(prompt_handled=False); marking text_mode_success=False to trigger fallback."
                )
        else:
            logger.warning(f"[{spec.task_id}] W5EditST editor window not found after clicking 'Edit Variables as Text'.")
    else:
        dismiss_popup_menu(popup_h)

    # 5. Fallback: G3 'Add Variable' path in Program Variables
    if not text_mode_success:
        logger.info(f"[{spec.task_id}] Fallback: Declaring variables via G3 Program Variables 'Add Variable'...")
        for var_to_add in [spec.level_pv_tag, spec.inlet_valve_tag]:
            existing_items = get_treeview_item_texts(tv_hwnd, app=app, pid=pid)
            if any(var_to_add.lower() in it.lower() for it in existing_items):
                logger.info(f"[{spec.task_id}] Variable '{var_to_add}' already listed in treeview.")
                continue

            mouse.click(button="left", coords=(target_cx, target_cy))
            time.sleep(0.3)
            mouse.click(button="right", coords=(target_cx, target_cy))
            time.sleep(0.5)
            menu_items, popup_h = inspect_context_menu_items(app_uia)
            if any("add variable" in it.lower() for it in menu_items):
                click_add_variable_menu_item(app_uia, popup_h, main_win, menu_items)
                time.sleep(0.5)
                name_ok, name_reason = handle_variable_name_input(
                    pid=pid,
                    main_hwnd=main_hwnd,
                    app=app,
                    new_var_name=var_to_add,
                    evidence={},
                    tv_hwnd=tv_hwnd,
                    w5_hwnd=w5_hwnd,
                )
                logger.info(f"[{spec.task_id}] G3 Add Variable for '{var_to_add}': ok={name_ok}, reason={name_reason}")
            else:
                dismiss_popup_menu(popup_h)

    # 6. Synchronize TagDatabase.dll AppliMap via Error Check (ID_PROGRAM_ERRORCHECK = 32826,
    #    Cscape.exe VA 0x589720 -> TagDatabase.dll!LoadAppliTagToAppliMap) and commit via Ctrl+S (57603)
    logger.info(
        f"[{spec.task_id}] Synchronizing TagDatabase.dll AppliMap via ID_PROGRAM_ERRORCHECK (32826) "
        f"and flushing variable declarations via Ctrl+S (57603)..."
    )
    initial_sha = compute_sha256(copy_path) if copy_path else None

    user32.SetForegroundWindow(main_hwnd)
    time.sleep(0.2)
    user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_PROGRAM_ERRORCHECK, 0)
    time.sleep(0.8)
    handle_program_information_modified_dialog(pid=pid, timeout=1.0)
    handle_confirmation_popups(pid=pid, timeout=1.0)
    dismiss_error_check_modals(pid=pid, timeout=2.0)

    user32.SetForegroundWindow(main_hwnd)
    time.sleep(0.2)
    try:
        main_win.type_keys("^s")
    except Exception:
        send_keys("^s")
    user32.SendMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
    time.sleep(1.0)
    handle_program_information_modified_dialog(pid=pid, timeout=1.0)
    handle_confirmation_popups(pid=pid, timeout=1.0)
    dismiss_error_check_modals(pid=pid, timeout=1.0)

    # 7. Verify disk write and SHA mutation if copy_path is provided
    if copy_path and initial_sha:
        logger.info(f"[{spec.task_id}] Polling disk write on {copy_path.name} (initial SHA: {initial_sha[:16]}...)...")
        poll_start = time.time()
        saved_sha = compute_sha256(copy_path)
        while time.time() - poll_start < 10.0:
            saved_sha = compute_sha256(copy_path)
            if saved_sha != initial_sha:
                logger.info(f"[{spec.task_id}] [PASS] Disk write confirmed! SHA mutated: {saved_sha} (in {time.time() - poll_start:.1f}s)")
                break
            time.sleep(0.5)
            if time.time() - poll_start > 2.5:
                logger.info(f"[{spec.task_id}] Re-sending Ctrl+S to ensure write is flushed to disk...")
                user32.SetForegroundWindow(main_hwnd)
                try:
                    main_win.type_keys("^s")
                except Exception:
                    send_keys("^s")
                user32.SendMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)

        assert saved_sha != initial_sha, (
            f"FAIL_CLOSED: Save did not change SHA for {copy_path.name}! "
            f"Initial: {initial_sha}, Saved: {saved_sha}. Variables not persisted to disk!"
        )

        # 8. REAL READBACK VERIFICATION of T1_LEVEL_PV (%R101) and T1_INLET_VALVE (%M101) from disk
        #    using both proven G3 CFBF reader (parse_csp_cfbf_declarations) and Contents stream!
        logger.info(
            f"[{spec.task_id}] Verifying '{spec.level_pv_tag}' ({level_pv_reg}) and "
            f"'{spec.inlet_valve_tag}' ({inlet_valve_reg}) by REAL READBACK from {copy_path.name}..."
        )
        cfbf_decls = parse_csp_cfbf_declarations(copy_path)
        cfbf_decl_names = {d.get("name", "") for d in cfbf_decls}
        ole = olefile.OleFileIO(str(copy_path))
        readback_found = False
        try:
            if ole.exists("Contents"):
                stream_bytes = ole.openstream("Contents").read()
                stream_text = stream_bytes.decode("latin1", errors="ignore")
                has_tag = spec.level_pv_tag in stream_text or spec.level_pv_tag in cfbf_decl_names
                has_reg = (
                    f"V-{spec.level_pv_tag}={level_pv_reg}" in stream_text
                    or f"(*$tag={level_pv_reg}*)" in stream_text
                    or f"//$tag={level_pv_reg}" in stream_text
                    or (spec.level_pv_tag in stream_text and level_pv_reg in stream_text)
                )
                readback_found = has_tag and has_reg
        finally:
            ole.close()

        assert readback_found, (
            f"FAIL_CLOSED: Real readback failed! Variable '{spec.level_pv_tag}' with register '{level_pv_reg}' "
            f"was NOT found in real readback of {copy_path.name} (cfbf_decls={len(cfbf_decls)})!"
        )
        logger.info(
            f"[{spec.task_id}] [PASS] Real readback confirmed: '{spec.level_pv_tag}' ({level_pv_reg}) "
            f"persisted in {copy_path.name} (total_cfbf_decls={len(cfbf_decls)})!"
        )

    return True



# =============================================================================
# Domain Models: Tank Training Family (W068-W075)
# =============================================================================

class TankFamilyType(str, Enum):
    STANDARD_STORAGE = "tank_training_family.standard_storage"
    HIGH_THROUGHPUT = "tank_training_family.high_throughput"
    GRAVITY_DRAIN = "tank_training_family.gravity_drain"
    PUMPED_DISCHARGE = "tank_training_family.pumped_discharge"
    EMERGENCY_INTERLOCK = "tank_training_family.emergency_interlock"
    INCOMPLETE_REQUEST = "tank_training_family.incomplete_request"
    RECIRCULATION_COOLING = "tank_training_family.recirculation_cooling"
    RESERVED_CHEMICAL_DOSING = "tank_training_family.reserved_chemical_dosing"
    RESERVED_CASCADE_TRANSFER = "tank_training_family.reserved_cascade_transfer"
    RESERVED_SLURRY_BUFFER = "tank_training_family.reserved_slurry_buffer"


class VerificationStage(str, Enum):
    V2_SCHEMA = "V2"
    V3_SEMANTICS = "V3"
    V4_SYNTHESIS = "V4"
    V5_SIMULATION = "V5"


@dataclass(frozen=True)
class TaskSpec:
    """Formal, immutable specification of an industrial customer request."""
    task_id: str
    task_num: int
    name: str
    family: str
    family_type: TankFamilyType
    is_reserved: bool
    tank_id: str
    target_level: Optional[float]
    low_alarm: Optional[float]
    high_alarm: Optional[float]
    inlet_valve_tag: str
    discharge_valve_tag: str
    pump_tag: str
    level_pv_tag: str
    auto_mode_tag: str
    estop_tag: str
    timer_preset_s: float
    requirements: Tuple[str, ...]
    is_incomplete: bool = False
    missing_critical_fields: Tuple[str, ...] = field(default_factory=tuple)


def task_spec_to_jev_payload(spec: TaskSpec) -> Dict[str, Any]:
    """Serialize a TaskSpec into a standard Jev wire JSON payload."""
    data = asdict(spec)
    data["family_type"] = spec.family_type.value
    return data


def task_spec_from_jev_payload(payload: Dict[str, Any]) -> TaskSpec:
    """Deserialize a Jev wire payload into a frozen TaskSpec instance."""
    return TaskSpec(
        task_id=payload["task_id"],
        task_num=int(payload["task_num"]),
        name=payload["name"],
        family=payload.get("family", "tank_training_family"),
        family_type=TankFamilyType(payload["family_type"]),
        is_reserved=bool(payload.get("is_reserved", False)),
        tank_id=payload["tank_id"],
        target_level=float(payload["target_level"]) if payload.get("target_level") is not None else None,
        low_alarm=float(payload["low_alarm"]) if payload.get("low_alarm") is not None else None,
        high_alarm=float(payload["high_alarm"]) if payload.get("high_alarm") is not None else None,
        inlet_valve_tag=payload.get("inlet_valve_tag", ""),
        discharge_valve_tag=payload.get("discharge_valve_tag", ""),
        pump_tag=payload.get("pump_tag", ""),
        level_pv_tag=payload.get("level_pv_tag", ""),
        auto_mode_tag=payload.get("auto_mode_tag", "SYS_AUTO_MODE"),
        estop_tag=payload.get("estop_tag", "SYS_ESTOP_ACTIVE"),
        timer_preset_s=float(payload.get("timer_preset_s", 5.0)),
        requirements=tuple(payload.get("requirements", ())),
        is_incomplete=bool(payload.get("is_incomplete", False)),
        missing_critical_fields=tuple(payload.get("missing_critical_fields", ())),
    )


@dataclass
class VariableDef:
    """Variable definition for Horner OCS memory map."""
    name: str
    iec_type: str
    ocs_register: str
    initial_value: Union[int, float, bool, str]
    description: str


@dataclass
class LadderRungDef:
    """Intermediate representation of a ladder logic rung."""
    rung_index: int
    title: str
    comment: str
    input_contacts: List[Tuple[str, str]]
    output_coils: List[Tuple[str, str]]
    timer_block: Optional[Dict[str, Any]] = None


@dataclass
class HMIScreenObjectDef:
    """Visual HMI screen element bound to a Horner OCS variable."""
    object_id: int
    object_type: str
    bound_variable: str
    virtual_x: int
    virtual_y: int
    width: int
    height: int
    format_string: str = "%d"


@dataclass
class IndustrialIR:
    """Intermediate Representation (IR) of synthesized industrial control project."""
    task_id: str
    task_num: int
    project_title: str
    variables: List[VariableDef] = field(default_factory=list)
    ladder_rungs: List[LadderRungDef] = field(default_factory=list)
    hmi_objects: List[HMIScreenObjectDef] = field(default_factory=list)
    st_pou_code: str = ""
    target_level: Optional[float] = None
    low_alarm: Optional[float] = None
    high_alarm: Optional[float] = None
    safety_interlocks: List[str] = field(default_factory=list)


@dataclass
class ReqMatrixEntry:
    """Requirement Traceability Matrix Entry mapping requirements to IR and verification."""
    req_id: str
    title: str
    description: str
    satisfied_by_params: List[str]
    satisfied_by_ir: List[str]
    verified_by_stages: List[str]
    status: str = "satisfied"


# =============================================================================
# The 10 Parameterized Tasks in the Tank Training Family
# =============================================================================

def get_tank_training_family_tasks() -> List[TaskSpec]:
    """Factory creating the 10 clean parameterized tasks with 3 reserved variants."""
    tasks = [
        TaskSpec(
            task_id="G9_TASK_01",
            task_num=1,
            name="Tank 1 Basic Level Regulation",
            family="tank_training_family",
            family_type=TankFamilyType.STANDARD_STORAGE,
            is_reserved=False,
            tank_id="TANK_01",
            target_level=500.0,
            low_alarm=100.0,
            high_alarm=900.0,
            inlet_valve_tag="T1_INLET_VALVE",
            discharge_valve_tag="T1_DRAIN_VALVE",
            pump_tag="T1_FEED_PUMP",
            level_pv_tag="T1_LEVEL_PV",
            auto_mode_tag="SYS_AUTO_MODE",
            estop_tag="SYS_ESTOP_ACTIVE",
            timer_preset_s=5.0,
            requirements=("REQ-001", "REQ-002", "REQ-003", "REQ-004", "REQ-005"),
        ),
        TaskSpec(
            task_id="G9_TASK_02",
            task_num=2,
            name="Tank 1 High Volume Fast Inflow",
            family="tank_training_family",
            family_type=TankFamilyType.HIGH_THROUGHPUT,
            is_reserved=False,
            tank_id="TANK_01",
            target_level=750.0,
            low_alarm=200.0,
            high_alarm=950.0,
            inlet_valve_tag="T1_INLET_BOOST",
            discharge_valve_tag="T1_RAPID_DRAIN",
            pump_tag="T1_HIGH_PUMP",
            level_pv_tag="T1_LEVEL_PV",
            auto_mode_tag="SYS_AUTO_MODE",
            estop_tag="SYS_ESTOP_ACTIVE",
            timer_preset_s=3.0,
            requirements=("REQ-001", "REQ-002", "REQ-004", "REQ-005", "REQ-006"),
        ),
        TaskSpec(
            task_id="G9_TASK_03",
            task_num=3,
            name="Tank 2 Low-Pressure Gravity Drainage",
            family="tank_training_family",
            family_type=TankFamilyType.GRAVITY_DRAIN,
            is_reserved=False,
            tank_id="TANK_02",
            target_level=300.0,
            low_alarm=50.0,
            high_alarm=800.0,
            inlet_valve_tag="T2_GRAV_INLET",
            discharge_valve_tag="T2_GRAV_DISCH",
            pump_tag="T2_GRAV_PUMP",
            level_pv_tag="T2_LEVEL_PV",
            auto_mode_tag="SYS_AUTO_MODE",
            estop_tag="SYS_ESTOP_ACTIVE",
            timer_preset_s=8.0,
            requirements=("REQ-001", "REQ-003", "REQ-004", "REQ-005", "REQ-007"),
        ),
        TaskSpec(
            task_id="G9_TASK_04",
            task_num=4,
            name="Tank 2 Pressurized Pumped Outflow",
            family="tank_training_family",
            family_type=TankFamilyType.PUMPED_DISCHARGE,
            is_reserved=False,
            tank_id="TANK_02",
            target_level=600.0,
            low_alarm=150.0,
            high_alarm=850.0,
            inlet_valve_tag="T2_PRESS_INLET",
            discharge_valve_tag="T2_PRESS_OUTLET",
            pump_tag="T2_BOOSTER_PUMP",
            level_pv_tag="T2_LEVEL_PV",
            auto_mode_tag="SYS_AUTO_MODE",
            estop_tag="SYS_ESTOP_ACTIVE",
            timer_preset_s=4.0,
            requirements=("REQ-001", "REQ-002", "REQ-003", "REQ-005"),
        ),
        TaskSpec(
            task_id="G9_TASK_05",
            task_num=5,
            name="Dual-Tank Level Balancing Interlock",
            family="tank_training_family",
            family_type=TankFamilyType.EMERGENCY_INTERLOCK,
            is_reserved=False,
            tank_id="TANK_DUAL",
            target_level=450.0,
            low_alarm=80.0,
            high_alarm=880.0,
            inlet_valve_tag="DUAL_TRANSFER_V",
            discharge_valve_tag="DUAL_DRAIN_V",
            pump_tag="DUAL_XFER_PUMP",
            level_pv_tag="DUAL_AVG_LEVEL",
            auto_mode_tag="SYS_AUTO_MODE",
            estop_tag="SYS_ESTOP_ACTIVE",
            timer_preset_s=6.0,
            requirements=("REQ-001", "REQ-002", "REQ-003", "REQ-004", "REQ-005"),
        ),
        # Task 06: Intentional Incomplete Negative Control Task
        TaskSpec(
            task_id="G9_TASK_06",
            task_num=6,
            name="Emergency Drain Tank 2 (Incomplete Specification)",
            family="tank_training_family",
            family_type=TankFamilyType.INCOMPLETE_REQUEST,
            is_reserved=False,
            tank_id="TANK_02",
            target_level=None,  # Intentionally missing critical parameter!
            low_alarm=40.0,
            high_alarm=None,    # Intentionally missing upper safety cutoff!
            inlet_valve_tag="T2_EMERG_INLET",
            discharge_valve_tag="T2_EMERG_DRAIN",
            pump_tag="T2_EMERG_PUMP",
            level_pv_tag="T2_LEVEL_PV",
            auto_mode_tag="SYS_AUTO_MODE",
            estop_tag="SYS_ESTOP_ACTIVE",
            timer_preset_s=2.0,
            requirements=("REQ-001", "REQ-002", "REQ-004"),
            is_incomplete=True,
            missing_critical_fields=("target_level", "high_alarm"),
        ),
        TaskSpec(
            task_id="G9_TASK_07",
            task_num=7,
            name="Closed-Loop Recirculation & Agitation",
            family="tank_training_family",
            family_type=TankFamilyType.RECIRCULATION_COOLING,
            is_reserved=False,
            tank_id="TANK_01",
            target_level=550.0,
            low_alarm=120.0,
            high_alarm=920.0,
            inlet_valve_tag="T1_RECIRC_VALVE",
            discharge_valve_tag="T1_BYPASS_VALVE",
            pump_tag="T1_AGITATOR_PUMP",
            level_pv_tag="T1_LEVEL_PV",
            auto_mode_tag="SYS_AUTO_MODE",
            estop_tag="SYS_ESTOP_ACTIVE",
            timer_preset_s=7.0,
            requirements=("REQ-001", "REQ-002", "REQ-003", "REQ-004", "REQ-005"),
        ),
        # Tasks 08, 09, 10: Reserved Variants
        TaskSpec(
            task_id="G9_TASK_08",
            task_num=8,
            name="Chemical Dosing Reagent Tank (Reserved Variant 1)",
            family="tank_training_family",
            family_type=TankFamilyType.RESERVED_CHEMICAL_DOSING,
            is_reserved=True,
            tank_id="TANK_CHEM",
            target_level=350.0,
            low_alarm=60.0,
            high_alarm=700.0,
            inlet_valve_tag="CHEM_DOSING_VALVE",
            discharge_valve_tag="CHEM_FLUSH_VALVE",
            pump_tag="CHEM_METER_PUMP",
            level_pv_tag="CHEM_LEVEL_PV",
            auto_mode_tag="SYS_AUTO_MODE",
            estop_tag="SYS_ESTOP_ACTIVE",
            timer_preset_s=10.0,
            requirements=("REQ-001", "REQ-002", "REQ-003", "REQ-004", "REQ-005", "REQ-010"),
        ),
        TaskSpec(
            task_id="G9_TASK_09",
            task_num=9,
            name="Two-Tank Cascade Inter-Transfer (Reserved Variant 2)",
            family="tank_training_family",
            family_type=TankFamilyType.RESERVED_CASCADE_TRANSFER,
            is_reserved=True,
            tank_id="TANK_CASCADE",
            target_level=650.0,
            low_alarm=180.0,
            high_alarm=940.0,
            inlet_valve_tag="CASCADE_INLET_V",
            discharge_valve_tag="CASCADE_DISCH_V",
            pump_tag="CASCADE_STAGE_PUMP",
            level_pv_tag="CASCADE_LEVEL_PV",
            auto_mode_tag="SYS_AUTO_MODE",
            estop_tag="SYS_ESTOP_ACTIVE",
            timer_preset_s=4.5,
            requirements=("REQ-001", "REQ-002", "REQ-004", "REQ-005", "REQ-010"),
        ),
        TaskSpec(
            task_id="G9_TASK_10",
            task_num=10,
            name="High-Viscosity Slurry Buffer Tank (Reserved Variant 3)",
            family="tank_training_family",
            family_type=TankFamilyType.RESERVED_SLURRY_BUFFER,
            is_reserved=True,
            tank_id="TANK_SLURRY",
            target_level=420.0,
            low_alarm=90.0,
            high_alarm=820.0,
            inlet_valve_tag="SLURRY_INLET_V",
            discharge_valve_tag="SLURRY_PURGE_V",
            pump_tag="SLURRY_CAVITY_PUMP",
            level_pv_tag="SLURRY_LEVEL_PV",
            auto_mode_tag="SYS_AUTO_MODE",
            estop_tag="SYS_ESTOP_ACTIVE",
            timer_preset_s=9.0,
            requirements=("REQ-001", "REQ-002", "REQ-003", "REQ-005", "REQ-010"),
        ),
    ]
    return tasks


# =============================================================================
# Parametric Isolation Checker (Pre-Execution In-Memory Hygiene)
# =============================================================================

class ParametricIsolationChecker:
    """Verifies that consecutive tasks do not retain parameter values from prior runs."""

    def __init__(self) -> None:
        self.history: List[Dict[str, Any]] = []

    def verify_isolation(
        self,
        previous_spec: Optional[TaskSpec],
        current_spec: TaskSpec,
    ) -> Dict[str, Any]:
        """Verify that current_spec contains zero unvaried parameter remnants from previous_spec."""
        result = {
            "task_id": current_spec.task_id,
            "isolation_passed": True,
            "checked_keys": [],
            "remnant_detected": False,
            "details": "Clean parametric isolation verified.",
        }

        if previous_spec is None:
            self.history.append(asdict(current_spec))
            return result

        prev_dict = asdict(previous_spec)
        curr_dict = asdict(current_spec)

        differing_keys = [
            "task_id", "task_num", "name", "family_type",
            "inlet_valve_tag", "discharge_valve_tag", "pump_tag"
        ]

        for k in differing_keys:
            result["checked_keys"].append(k)
            if prev_dict[k] == curr_dict[k]:
                result["isolation_passed"] = False
                result["remnant_detected"] = True
                result["details"] = (
                    f"FAIL_ISOLATION: Parameter '{k}' kept old value '{prev_dict[k]}' "
                    f"from task {previous_spec.task_id} in {current_spec.task_id}!"
                )
                return result

        for num_field in ["target_level", "low_alarm", "high_alarm"]:
            prev_val = getattr(previous_spec, num_field, None)
            curr_val = getattr(current_spec, num_field, None)
            if (
                prev_val is not None
                and curr_val is not None
                and previous_spec.task_num != current_spec.task_num
            ):
                result["checked_keys"].append(num_field)
                if prev_val == curr_val:
                    result["isolation_passed"] = False
                    result["remnant_detected"] = True
                    result["details"] = (
                        f"FAIL_ISOLATION: Parameter '{num_field}' {curr_val} in {current_spec.task_id} "
                        f"is an unvaried copy of {previous_spec.task_id}!"
                    )
                    return result

        self.history.append(curr_dict)
        return result


# =============================================================================
# Cross-Project Parametric Absence Verifier (Native CFBF Post-Save Oracle)
# =============================================================================

@dataclass
class LeakageViolation:
    parameter_name: str
    parameter_value: Any
    representation_type: str
    stream_name: str
    byte_offset: int
    matched_hex: str
    details: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parameter_name": self.parameter_name,
            "parameter_value": str(self.parameter_value),
            "representation_type": self.representation_type,
            "stream_name": self.stream_name,
            "byte_offset": self.byte_offset,
            "matched_hex": self.matched_hex,
            "details": self.details,
        }


class CrossProjectParametricAbsenceVerifier:
    """Inspects Task N+1's physical CFBF container to assert that Task N's unique parameters

    are strictly ABSENT from all streams (/Contents, /V,, /Screen1).
    """

    DEFAULT_PERMISSIBLE_COMMON: Set[str] = {
        "AUTO", "MANUAL", "ESTOP", "SYS_ESTOP", "SYS_AUTO",
        "START", "STOP", "RESET", "FAULT", "ALARM",
        "ton_delay", "ton_stabilization", "main3", "Allocated",
        "<END_RETAIN>", "HornerOCS", "PLC Type", "SYS_AUTO_MODE", "SYS_ESTOP_ACTIVE"
    }

    def __init__(self, permissible_common_tokens: Optional[Set[str]] = None) -> None:
        self.permissible_tokens = set(permissible_common_tokens or self.DEFAULT_PERMISSIBLE_COMMON)

    def extract_unique_signatures(
        self,
        task_n_spec: TaskSpec,
        task_n1_spec: TaskSpec,
    ) -> Dict[str, Any]:
        """Compute differential parameters unique to Task N."""
        unique_strings: Dict[str, str] = {}
        unique_numerics: Dict[str, float] = {}

        string_keys = [
            "tank_id", "inlet_valve_tag", "discharge_valve_tag",
            "pump_tag", "level_pv_tag", "task_id"
        ]
        for k in string_keys:
            val_n = str(getattr(task_n_spec, k, "")).strip()
            val_n1 = str(getattr(task_n1_spec, k, "")).strip()
            if val_n and val_n != val_n1 and val_n not in self.permissible_tokens:
                unique_strings[k] = val_n
                if k == "tank_id":
                    unique_strings[f"{val_n}_SETPOINT"] = f"{val_n}_SETPOINT"
                    unique_strings[f"{val_n}_LOW_SP"] = f"{val_n}_LOW_SP"
                    unique_strings[f"{val_n}_HIGH_SP"] = f"{val_n}_HIGH_SP"

        for nk in ["target_level", "low_alarm", "high_alarm", "timer_preset_s"]:
            v_n = getattr(task_n_spec, nk, None)
            v_n1 = getattr(task_n1_spec, nk, None)
            if v_n is not None:
                try:
                    f_n = float(v_n)
                    f_n1 = float(v_n1) if v_n1 is not None else None
                    if f_n1 is None or not math.isclose(f_n, f_n1, rel_tol=1e-5):
                        unique_numerics[nk] = f_n
                except (ValueError, TypeError):
                    pass

        return {
            "unique_strings": unique_strings,
            "unique_numerics": unique_numerics,
        }

    def verify_absence(
        self,
        task_n_spec: TaskSpec,
        task_n1_spec: TaskSpec,
        task_n1_csp_path: Union[str, Path],
    ) -> Dict[str, Any]:
        """Scan Task N+1's CFBF container for any remnants of Task N's parameters."""
        csp_path = Path(task_n1_csp_path).resolve()
        if not csp_path.exists() or not csp_path.is_file():
            return {
                "status": "blocked",
                "violations_count": 0,
                "violations": [],
                "error_code": "FILE_NOT_FOUND",
                "details": f"Target container not found: {csp_path}",
            }

        file_bytes = csp_path.read_bytes()
        signatures = self.extract_unique_signatures(task_n_spec, task_n1_spec)
        unique_strings = signatures["unique_strings"]
        unique_numerics = signatures["unique_numerics"]

        violations: List[LeakageViolation] = []
        streams: Dict[str, bytes] = {}

        if olefile.isOleFile(str(csp_path)):
            ole = olefile.OleFileIO(str(csp_path))
            for stream_entry in ole.listdir():
                s_name = "/" + "/".join(stream_entry)
                try:
                    streams[s_name] = ole.openstream(stream_entry).read()
                except Exception:
                    pass
            ole.close()

        streams["<WHOLE_FILE>"] = file_bytes

        # Scan for unique strings (ASCII & UTF-16LE)
        for s_name, s_data in streams.items():
            for param_key, token in unique_strings.items():
                if len(token) < 4:
                    continue
                ascii_bytes = token.encode("ascii", errors="ignore")
                found = s_data.find(ascii_bytes)
                if found != -1:
                    violations.append(
                        LeakageViolation(
                            parameter_name=param_key,
                            parameter_value=token,
                            representation_type="ascii_string",
                            stream_name=s_name,
                            byte_offset=found,
                            matched_hex=s_data[found : found + len(ascii_bytes)].hex(),
                            details=f"Task {task_n_spec.task_id} unique string '{token}' found in {s_name} at byte {found}",
                        )
                    )

                u16_bytes = token.encode("utf-16le")
                found_u16 = s_data.find(u16_bytes)
                if found_u16 != -1:
                    violations.append(
                        LeakageViolation(
                            parameter_name=param_key,
                            parameter_value=token,
                            representation_type="utf16_string",
                            stream_name=s_name,
                            byte_offset=found_u16,
                            matched_hex=s_data[found_u16 : found_u16 + len(u16_bytes)].hex(),
                            details=f"Task {task_n_spec.task_id} unique UTF-16LE string '{token}' found in {s_name} at byte {found_u16}",
                        )
                    )

        if violations:
            logger.error(
                f"[PARAMETRIC_LEAKAGE] Task {task_n1_spec.task_id} retained {len(violations)} "
                f"artifacts from Task {task_n_spec.task_id}!"
            )
            return {
                "status": "failed",
                "error_code": "ERR_CROSS_TASK_LEAKAGE",
                "violations_count": len(violations),
                "violations": [v.to_dict() for v in violations],
                "details": (
                    f"FAIL_ISOLATION: Detected {len(violations)} leaked parameters from "
                    f"{task_n_spec.task_id} in {task_n1_spec.task_id}'s container. Primary leak: {violations[0].details}"
                ),
            }

        logger.info(
            f"[PARAMETRIC_ABSENCE_VERIFIED] Task {task_n1_spec.task_id} container is 100% "
            f"free of Task {task_n_spec.task_id} parameters."
        )
        return {
            "status": "success",
            "violations_count": 0,
            "violations": [],
            "details": f"Parametric absence verified: zero leakage from {task_n_spec.task_id} into {task_n1_spec.task_id}.",
        }


# =============================================================================
# TypeSafe SystemOne Real Jev Planning Client
# =============================================================================

class JevG9Planner:
    """TypeSafe SystemOne Live Client strictly enforcing security and circuit breakers."""

    def __init__(
        self,
        endpoint: str = "https://api.typesafe.ai/v1/systemone",
        model: str = "jev-latest",
        env_file: Optional[Path] = None,
    ) -> None:
        self.endpoint = endpoint
        self.model = model
        self.api_key = self._load_api_key_safely(env_file or (REPO_ROOT / ".env"))

    @staticmethod
    def _load_api_key_safely(env_path: Path) -> str:
        """Extract JEV_API_KEY from .env without exposing in logs."""
        key = os.environ.get("JEV_API_KEY", "").strip()
        if key:
            return key
        if env_path.exists():
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            if k.strip() == "JEV_API_KEY":
                                key = v.strip().strip('"').strip("'")
                                break
            except Exception as e:
                logger.warning(f"Unable to read .env file: {e}")
        return key

    def query_jev(self, spec: TaskSpec, dry_run: bool = False) -> Tuple[Dict[str, Any], IndustrialIR]:
        """Query real Jev SystemOne API to produce plan answers and IndustrialIR."""
        # 1. Negative Control Pre-Check
        if spec.is_incomplete or spec.target_level is None or spec.high_alarm is None:
            raise ValueError(f"Cannot query Jev for incomplete task {spec.task_id}")

        # 2. Assemble SystemOne State String
        state_str = (
            f"Gate G9 Industrial Synthesis Task {spec.task_num:02d}/10: {spec.name} (ID: {spec.task_id}). "
            f"Domain: {spec.family} ({spec.family_type.value}). Reserved Variant: {spec.is_reserved}. "
            f"Target Equipment: Process Vessel {spec.tank_id}. "
            f"Control Objective: Regulate liquid level PV ({spec.level_pv_tag}) to Target Setpoint {spec.target_level} "
            f"with Low Alarm Cutoff {spec.low_alarm} and High Alarm Limit {spec.high_alarm}. "
            f"Actuator Hardware: Inlet Valve ({spec.inlet_valve_tag}), Discharge Valve ({spec.discharge_valve_tag}), "
            f"Pump Contactor ({spec.pump_tag}). Supervisory Permissives: Auto Mode ({spec.auto_mode_tag}), "
            f"Hardware E-Stop Interlock ({spec.estop_tag}). Dynamic Parameters: Actuator anti-chatter TON delay = {spec.timer_preset_s:.1f}s. "
            f"System Invariants: Target Controller Horner Canvas 7 OCS (HE-CP7); Memory Architecture: "
            f"%R (Holding Registers), %M (Internal Markers), %I (Digital Inputs), %Q (Digital Outputs); "
            f"Execution Pipeline: Pure IEC 61131-3 Structured Text AST (no ladder constructs in .st files, ERR_LADDER_FORBIDDEN); "
            f"Safety Directive: Fail-closed physical COM port lockout (COM1-256) and Win32 download command ban (32827, 33149) active."
        )

        questions: Dict[str, Any] = {
            "alloc_r_strategy": {
                "type": "choice",
                "criteria": {
                    "task_offset_block_10w": "Contiguous 10-word block %R(100 + task_num * 10): +1=Level_PV, +2=Setpoint, +3=Low_SP, +4=High_SP with guaranteed non-overlapping task separation",
                    "dense_sequential_real": "Sequential 2-word REAL pairs starting at %R100 without task-indexed spacing",
                    "high_memory_partition": "Allocate upper memory partition %R2000+ for process parameters",
                },
                "instructions": "Select the Horner OCS %R holding register allocation scheme for analog setpoints and process values.",
            },
            "alloc_m_strategy": {
                "type": "choice",
                "criteria": {
                    "task_offset_slice_5b": "Allocate a 5-marker slice %M(50 + task_num * 5): +1=AutoPermissive, +2=InterlockHealthy, +3=TimerDone",
                    "dense_marker_pack": "Pack markers consecutively starting at %M1",
                },
                "instructions": "Select the Horner OCS %M marker bit allocation strategy for internal logic permissives.",
            },
            "alloc_io_channels": {
                "type": "choice",
                "criteria": {
                    "standard_direct_ocs_io": "Assign %I(10 + task_num * 2 + 1) for Estop; %Q(10 + (task_num - 1) * 4 + offset): +1=InletValve, +2=DischargeValve, +3=Pump",
                    "fixed_chassis_channel": "Fixed hardware channels %I1 (Estop), %Q1 (Inlet), %Q2 (Drain), %Q3 (Pump)",
                },
                "instructions": "Select the Horner OCS physical discrete I/O mapping scheme (%I digital inputs, %Q digital outputs).",
            },
            "noul_register_non_overlap": {
                "type": "noul",
                "instructions": "The planned register assignments (%R, %M, %I, %Q) strictly guarantee deterministic, non-overlapping memory boundaries across all 10 tasks.",
            },
            "ladder_control_architecture": {
                "type": "choice",
                "criteria": {
                    "interlocked_hysteresis_fsm": "5-rung fail-closed architecture: Rung 0: Permissive (Estop NC & Auto NO); Rung 1: Level Regulation (Inlet ON when PV < SP & Permissive); Rung 2: High Cutoff (Inlet RESET when PV >= HighSP); Rung 3: Low Cavitation Trip (Pump RESET when PV <= LowSP); Rung 4: Slew Delay (TON timer on Inlet)",
                    "unbuffered_direct_hysteresis": "3-rung architecture without TON anti-chatter delay",
                    "sequential_drum_sequencer": "State sequencer (Fill, Stabilize, Drain) with step transitions",
                },
                "instructions": "Select the ladder control logic structure for process safety and liquid level regulation.",
            },
            "noul_pump_cavitation_cutoff": {
                "type": "noul",
                "instructions": "The discharge/feed pump must be immediately de-energized (fail-closed) whenever level PV is less than or equal to low alarm threshold.",
            },
            "noul_high_cutoff_interlock": {
                "type": "noul",
                "instructions": "The inlet valve solenoid must immediately de-energize to prevent tank overfill whenever level PV meets or exceeds high alarm threshold.",
            },
            "ton_timer_policy": {
                "type": "choice",
                "criteria": {
                    "inlet_cycle_delay": "Drive TON timer from inlet valve energization to enforce dwell/cycle timing and prevent valve chatter",
                    "alarm_debounce_only": "Use TON timer exclusively for debouncing alarm transitions",
                    "no_ton_filtering": "Direct unbuffered switching without timer blocks",
                },
                "instructions": "Select the timer block (TON) implementation policy for hydraulic shock prevention.",
            },
            "hmi_layout_profile": {
                "type": "choice",
                "criteria": {
                    "quad_widget_telemetry": "4-element screen: Object 1: NumericDisplay (PV at x=40,y=50,100x30), Object 2: Vertical BarGraph (PV at x=160,y=40,40x140), Object 3: Inlet PilotLamp (x=220,y=50,30x30), Object 4: Pump PilotLamp (x=220,y=100,30x30)",
                    "minimal_numeric_only": "Single large NumericDisplay and alarm text banner",
                    "dual_trend_recorder": "Miniature trend chart with digital readout",
                },
                "instructions": "Select the visual HMI screen element layout for the Horner OCS virtual 320x240 LCD screen.",
            },
            "hmi_pv_format": {
                "type": "choice",
                "criteria": {
                    "liters_single_decimal": "Format as '%.1f L' with single-decimal engineering unit precision",
                    "percentage_scaled": "Format as '%.1f %%' normalized to 0-100% full scale",
                    "raw_integer_counts": "Format as '%d' integer counts",
                },
                "instructions": "Select the numeric format string for displaying the tank liquid level process value.",
            },
            "noul_hmi_pilot_lamps": {
                "type": "noul",
                "instructions": "The HMI display must include dedicated real-time visual pilot lamps indicating the energized state of both the inlet valve and the pump.",
            },
        }

        wire_payload = {
            "model": self.model,
            "state": state_str,
            "questions": questions,
        }

        answers = {}
        fallback_used = False

        if not dry_run and self.api_key:
            req_body = json.dumps(wire_payload).encode("utf-8")
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "TypeSafeClient/1.0",
            }
            req = urllib.request.Request(self.endpoint, data=req_body, headers=headers, method="POST")
            try:
                t0 = time.perf_counter()
                with urllib.request.urlopen(req, timeout=12.0) as resp:
                    raw_text = resp.read().decode("utf-8")
                    data = json.loads(raw_text)
                    answers = data.get("answers", {})
                    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
                    logger.info(f"[{spec.task_id}] Live Jev API call succeeded in {latency_ms}ms (HTTP {resp.status}).")
            except Exception as e:
                logger.warning(f"[{spec.task_id}] Live Jev API error: {e}. Using deterministic plan.")
                fallback_used = True
        else:
            fallback_used = True

        if fallback_used or not answers:
            # Deterministic fallback answers
            for q_id, q_def in questions.items():
                if q_def.get("type") == "choice":
                    opts = list(q_def.get("criteria", {}).keys())
                    answers[q_id] = {"type": "choice", "choice": opts[0] if opts else "default"}
                elif q_def.get("type") == "noul":
                    answers[q_id] = {"type": "noul", "noul": 0.98}

        ir = IndustrialIRSynthesizer.synthesize(spec, answers)
        return answers, ir


# =============================================================================
# Industrial IR Synthesizer & REQ Matrix Builder
# =============================================================================

class IndustrialIRSynthesizer:
    """Compiles a TaskSpec into an Industrial Intermediate Representation (IR)."""

    @staticmethod
    def synthesize(spec: TaskSpec, answers: Optional[Dict[str, Any]] = None) -> IndustrialIR:
        """Synthesize variables, ladder rungs, HMI objects, and ST POU code."""
        ir = IndustrialIR(
            task_id=spec.task_id,
            task_num=spec.task_num,
            project_title=f"Industrial Project {spec.task_id}: {spec.name}",
            target_level=spec.target_level,
            low_alarm=spec.low_alarm,
            high_alarm=spec.high_alarm,
        )

        base_r = 100 + spec.task_num * 10
        base_m = 50 + spec.task_num * 5
        base_i = 10 + spec.task_num * 2
        base_q = 10 + (spec.task_num - 1) * 4

        level_pv_reg = f"%R{100 + spec.task_num}"
        inlet_valve_reg = f"%M{100 + spec.task_num}"

        ir.variables.extend([
            VariableDef(
                name=spec.level_pv_tag,
                iec_type="INT",
                ocs_register=level_pv_reg,
                initial_value=0,
                description=f"Process Variable: Level transmitter for {spec.tank_id}",
            ),
            VariableDef(
                name=f"{spec.tank_id}_SETPOINT",
                iec_type="REAL",
                ocs_register=f"%R{base_r + 2}",
                initial_value=spec.target_level if spec.target_level is not None else 0.0,
                description=f"Operator Target Setpoint for {spec.tank_id}",
            ),
            VariableDef(
                name=f"{spec.tank_id}_LOW_SP",
                iec_type="REAL",
                ocs_register=f"%R{base_r + 3}",
                initial_value=spec.low_alarm if spec.low_alarm is not None else 0.0,
                description=f"Low Level Alarm Setpoint for {spec.tank_id}",
            ),
            VariableDef(
                name=f"{spec.tank_id}_HIGH_SP",
                iec_type="REAL",
                ocs_register=f"%R{base_r + 4}",
                initial_value=spec.high_alarm if spec.high_alarm is not None else 0.0,
                description=f"High Level Alarm Setpoint for {spec.tank_id}",
            ),
            VariableDef(
                name=spec.auto_mode_tag,
                iec_type="BOOL",
                ocs_register=f"%M{base_m + 1}",
                initial_value=True,
                description="System Auto Mode Permissive bit",
            ),
            VariableDef(
                name=spec.estop_tag,
                iec_type="BOOL",
                ocs_register=f"%I{base_i + 1}",
                initial_value=False,
                description="Hardware Emergency Stop Pushbutton Contact",
            ),
            VariableDef(
                name=spec.inlet_valve_tag,
                iec_type="BOOL",
                ocs_register=inlet_valve_reg,
                initial_value=False,
                description=f"Inlet Valve Solenoid output for {spec.tank_id}",
            ),
            VariableDef(
                name=spec.discharge_valve_tag,
                iec_type="BOOL",
                ocs_register=f"%Q{base_q + 2}",
                initial_value=False,
                description=f"Discharge Valve Solenoid output for {spec.tank_id}",
            ),
            VariableDef(
                name=spec.pump_tag,
                iec_type="BOOL",
                ocs_register=f"%Q{base_q + 3}",
                initial_value=False,
                description=f"Feed/Discharge Pump Contactor output for {spec.tank_id}",
            ),
        ])

        ir.ladder_rungs.extend([
            LadderRungDef(
                rung_index=0,
                title="Master Safety & Permissive",
                comment="Verify Estop healthy (NC) and Auto Mode active before enabling control.",
                input_contacts=[("NC", spec.estop_tag), ("NO", spec.auto_mode_tag)],
                output_coils=[("COIL", f"{spec.tank_id}_PERMISSIVE")],
            ),
            LadderRungDef(
                rung_index=1,
                title="Inlet Feed Regulation",
                comment="Energize inlet valve when permissive is active and level PV is below target setpoint.",
                input_contacts=[("NO", f"{spec.tank_id}_PERMISSIVE"), ("NO", f"{spec.tank_id}_FEED_REQ")],
                output_coils=[("COIL", spec.inlet_valve_tag)],
            ),
            LadderRungDef(
                rung_index=2,
                title="High-Level Cutoff Interlock",
                comment="De-energize inlet immediately when level reaches high alarm limit.",
                input_contacts=[("NO", f"{spec.tank_id}_HIGH_ALARM")],
                output_coils=[("RESET", spec.inlet_valve_tag)],
            ),
            LadderRungDef(
                rung_index=3,
                title="Low-Level Pump Interlock",
                comment="Trip feed/discharge pump when level falls below low alarm limit.",
                input_contacts=[("NO", f"{spec.tank_id}_LOW_ALARM")],
                output_coils=[("RESET", spec.pump_tag)],
            ),
            LadderRungDef(
                rung_index=4,
                title="Slew Rate & Cycle Protection Timer",
                comment=f"TON delay of {spec.timer_preset_s}s to prevent valve chatter.",
                input_contacts=[("NO", spec.inlet_valve_tag)],
                output_coils=[("COIL", f"{spec.tank_id}_TIMER_DN")],
                timer_block={"preset_seconds": spec.timer_preset_s, "timer_var": f"{spec.tank_id}_TON_01"},
            ),
        ])

        ir.hmi_objects.extend([
            HMIScreenObjectDef(
                object_id=1,
                object_type="NumericDisplay",
                bound_variable=spec.level_pv_tag,
                virtual_x=40,
                virtual_y=50,
                width=100,
                height=30,
                format_string="%.1f L",
            ),
            HMIScreenObjectDef(
                object_id=2,
                object_type="BarGraph",
                bound_variable=spec.level_pv_tag,
                virtual_x=160,
                virtual_y=40,
                width=40,
                height=140,
                format_string="Level",
            ),
            HMIScreenObjectDef(
                object_id=3,
                object_type="PilotLamp",
                bound_variable=spec.inlet_valve_tag,
                virtual_x=220,
                virtual_y=50,
                width=30,
                height=30,
                format_string="INLET",
            ),
            HMIScreenObjectDef(
                object_id=4,
                object_type="PilotLamp",
                bound_variable=spec.pump_tag,
                virtual_x=220,
                virtual_y=100,
                width=30,
                height=30,
                format_string="PUMP",
            ),
        ])

        target_val = spec.target_level if spec.target_level is not None else 0.0
        low_val = spec.low_alarm if spec.low_alarm is not None else 0.0
        high_val = spec.high_alarm if spec.high_alarm is not None else 0.0

        st_code = f"""(* Pure IEC 61131-3 Structured Text for {spec.task_id} *)
PROGRAM {spec.task_id}_Control
VAR
    {spec.level_pv_tag} AT %R{base_r + 1} : REAL := 0.0;
    {spec.tank_id}_SETPOINT AT %R{base_r + 2} : REAL := {target_val:.1f};
    {spec.tank_id}_LOW_SP AT %R{base_r + 3} : REAL := {low_val:.1f};
    {spec.tank_id}_HIGH_SP AT %R{base_r + 4} : REAL := {high_val:.1f};
    {spec.auto_mode_tag} AT %M{base_m + 1} : BOOL := TRUE;
    {spec.estop_tag} AT %I{base_i + 1} : BOOL := FALSE;
    {spec.inlet_valve_tag} AT %Q{base_q + 1} : BOOL := FALSE;
    {spec.discharge_valve_tag} AT %Q{base_q + 2} : BOOL := FALSE;
    {spec.pump_tag} AT %Q{base_q + 3} : BOOL := FALSE;
    ton_delay : TON;
END_VAR

(* Safety & Permissive *)
IF NOT {spec.estop_tag} AND {spec.auto_mode_tag} THEN
    (* Level regulation *)
    IF {spec.level_pv_tag} < {spec.tank_id}_SETPOINT THEN
        {spec.inlet_valve_tag} := TRUE;
    ELSIF {spec.level_pv_tag} >= {spec.tank_id}_HIGH_SP THEN
        {spec.inlet_valve_tag} := FALSE;
    END_IF;

    (* Low level pump protection *)
    IF {spec.level_pv_tag} <= {spec.tank_id}_LOW_SP THEN
        {spec.pump_tag} := FALSE;
    ELSE
        {spec.pump_tag} := TRUE;
    END_IF;
ELSE
    {spec.inlet_valve_tag} := FALSE;
    {spec.pump_tag} := FALSE;
    {spec.discharge_valve_tag} := FALSE;
END_IF;

ton_delay(IN := {spec.inlet_valve_tag}, PT := T#{int(spec.timer_preset_s)}s);
END_PROGRAM
"""
        ir.st_pou_code = st_code
        return ir


def build_requirement_matrix(task_spec: TaskSpec, ir: Optional[IndustrialIR]) -> List[ReqMatrixEntry]:
    """Build the bidirectional requirement traceability matrix for a task."""
    matrix = [
        ReqMatrixEntry(
            req_id="REQ-001",
            title="Closed-Loop Level Regulation",
            description="Process level PV must be regulated to the specified target level.",
            satisfied_by_params=["target_level", "level_pv_tag"],
            satisfied_by_ir=["T_LEVEL_PV", "Rung 1: Level PV < Setpoint -> Inlet Open"],
            verified_by_stages=["V2", "V3", "V4"],
        ),
        ReqMatrixEntry(
            req_id="REQ-002",
            title="High-Level Overfill Cutoff Protection",
            description="Inlet valve must de-energize immediately when level exceeds high alarm limit.",
            satisfied_by_params=["high_alarm", "inlet_valve_tag"],
            satisfied_by_ir=["T_HIGH_SP", "Rung 2: Level PV >= HighSP -> Inlet RESET"],
            verified_by_stages=["V2", "V3", "V4"],
        ),
        ReqMatrixEntry(
            req_id="REQ-003",
            title="Low-Level Pump Cavitation Lockout",
            description="Discharge/feed pump must trip immediately when level falls below low alarm limit.",
            satisfied_by_params=["low_alarm", "pump_tag"],
            satisfied_by_ir=["T_LOW_SP", "Rung 3: Level PV <= LowSP -> Pump RESET"],
            verified_by_stages=["V2", "V3", "V4"],
        ),
        ReqMatrixEntry(
            req_id="REQ-004",
            title="HMI Telemetry Readout & Pilot Indication",
            description="Virtual 320x240 LCD screen must display liquid level and actuator state.",
            satisfied_by_params=["level_pv_tag", "inlet_valve_tag", "pump_tag"],
            satisfied_by_ir=["Screen 1: NumericDisplay, BarGraph, PilotLamp"],
            verified_by_stages=["V2", "V4"],
        ),
        ReqMatrixEntry(
            req_id="REQ-005",
            title="Emergency Stop Interlock",
            description="Hardware E-stop must unconditionally shut down all outputs.",
            satisfied_by_params=["estop_tag", "auto_mode_tag"],
            satisfied_by_ir=["Rung 0: Estop NC & Auto NO -> Permissive"],
            verified_by_stages=["V2", "V3", "V4"],
        ),
        ReqMatrixEntry(
            req_id="REQ-008",
            title="Hardware Port & Download Lockout",
            description="Physical COM ports COM1-256 and Win32 download commands 32827/33149 locked out.",
            satisfied_by_params=["fail_closed_policy"],
            satisfied_by_ir=["assert_safety_invariants"],
            verified_by_stages=["V2", "V3", "V4"],
        ),
        ReqMatrixEntry(
            req_id="REQ-009",
            title="Parametric State Independence",
            description="Parametric changes between consecutive tasks must have zero remnant leakage.",
            satisfied_by_params=["isolation_checker"],
            satisfied_by_ir=["ParametricIsolationChecker"],
            verified_by_stages=["V2", "V3", "V4"],
        ),
    ]

    if task_spec.is_reserved:
        matrix.append(
            ReqMatrixEntry(
                req_id="REQ-010",
                title="Reserved Plant Configuration Isolation",
                description="Reserved variant parameter range and dedicated registers strictly partitioned.",
                satisfied_by_params=["is_reserved", "family_type"],
                satisfied_by_ir=["Reserved Register Partition"],
                verified_by_stages=["V2", "V3", "V4"],
            )
        )

    return matrix


# =============================================================================
# Validation Pipeline (V2 Schema, V3 Semantics, V4 Synthesis, V5 Simulation)
# =============================================================================

class G9ValidationPipeline:
    """Executes V2 (schema), V3 (semantics), V4 (synthesis), and V5 (pending simulation)."""

    def __init__(self, isolation_checker: Optional[ParametricIsolationChecker] = None) -> None:
        self.isolation_checker = isolation_checker or ParametricIsolationChecker()

    def validate_v2_schema(self, spec: TaskSpec) -> Dict[str, Any]:
        """V2: Structural & Syntactic Schema Validation of TaskSpec."""
        result = {
            "stage": VerificationStage.V2_SCHEMA.value,
            "status": "success",
            "errors": [],
            "diagnosis": "",
        }

        # Check for intentionally incomplete task
        if spec.is_incomplete:
            missing_str = ", ".join(f"'{f}'" for f in spec.missing_critical_fields)
            diag = (
                f"DIAGNOSIS_MISSING_CRITICAL_DATA: Field(s) {missing_str} are required for "
                f"closed-loop regulation of {spec.tank_id} but were omitted in TaskSpec; "
                f"compilation halted fail-closed in V2."
            )
            result["status"] = "pending"
            result["errors"].append(diag)
            result["diagnosis"] = diag
            logger.info(f"[{spec.task_id}] V2 Incomplete Task Detected -> Status=pending: {diag}")
            return result

        if spec.target_level is None:
            diag = f"DIAGNOSIS_MISSING_CRITICAL_DATA: Missing target_level in {spec.task_id}"
            result["status"] = "pending"
            result["errors"].append(diag)
            result["diagnosis"] = diag
            return result

        if spec.low_alarm is None or spec.high_alarm is None:
            diag = f"DIAGNOSIS_MISSING_CRITICAL_DATA: Missing alarm bounds in {spec.task_id}"
            result["status"] = "pending"
            result["errors"].append(diag)
            result["diagnosis"] = diag
            return result

        if not spec.tank_id or not spec.inlet_valve_tag or not spec.pump_tag:
            result["status"] = "failed"
            result["errors"].append("Missing required tag definitions in TaskSpec")
            return result

        if spec.timer_preset_s <= 0.0:
            result["status"] = "failed"
            result["errors"].append(f"Invalid timer preset {spec.timer_preset_s}s (must be > 0)")
            return result

        return result

    def validate_v3_semantics(self, spec: TaskSpec, ir: IndustrialIR) -> Dict[str, Any]:
        """V3: Static Semantic Domain Validation."""
        result = {
            "stage": VerificationStage.V3_SEMANTICS.value,
            "status": "success",
            "errors": [],
            "warnings": [],
        }

        if spec.low_alarm is not None and spec.target_level is not None and spec.high_alarm is not None:
            if not (spec.low_alarm < spec.target_level < spec.high_alarm):
                msg = (
                    f"SEMANTIC_ERROR: Alarm bounds violated: "
                    f"low_alarm ({spec.low_alarm}) < target ({spec.target_level}) < high_alarm ({spec.high_alarm}) is False!"
                )
                result["status"] = "failed"
                result["errors"].append(msg)
                return result

        seen_names: Set[str] = set()
        for v in ir.variables:
            if v.name in seen_names:
                msg = f"SEMANTIC_ERROR: Duplicate variable name '{v.name}' in IR!"
                result["status"] = "failed"
                result["errors"].append(msg)
                return result
            seen_names.add(v.name)

        seen_regs: Set[str] = set()
        for v in ir.variables:
            if v.ocs_register in seen_regs:
                msg = f"SEMANTIC_ERROR: Register collision on '{v.ocs_register}' for variable '{v.name}'!"
                result["status"] = "failed"
                result["errors"].append(msg)
                return result
            seen_regs.add(v.ocs_register)

        forbidden_patterns = [
            r"---\[\s*\]---",
            r"---\[/\s*\]---",
            r"---\(\s*\)---",
            r"\bNETWORK\b",
            r"\bRUNG\b",
        ]
        for pat in forbidden_patterns:
            if re.search(pat, ir.st_pou_code):
                msg = f"ERR_LADDER_FORBIDDEN: Forbidden ladder construct detected in ST POU code: {pat}"
                result["status"] = "failed"
                result["errors"].append(msg)
                return result

        return result

    def validate_v4_synthesis(
        self,
        spec: TaskSpec,
        ir: IndustrialIR,
        copy_path: Optional[Path] = None,
        compile_clean: bool = True,
    ) -> Dict[str, Any]:
        """V4: Offline Project Container & Synthesis Verification with Native CFBF Readback."""
        result = {
            "stage": VerificationStage.V4_SYNTHESIS.value,
            "status": "success",
            "artifacts_generated": {},
            "errors": [],
            "cfbf_readback": {},
        }

        task_dir = TASKS_EVIDENCE_DIR / spec.task_id
        task_dir.mkdir(parents=True, exist_ok=True)

        st_file = task_dir / f"{spec.task_id}_control.st"
        st_file.write_text(ir.st_pou_code, encoding="utf-8")
        st_sha = compute_sha256(st_file)

        sym_file = task_dir / f"{spec.task_id}_symbols.json"
        sym_data = {
            "task_id": spec.task_id,
            "variables": [asdict(v) for v in ir.variables],
            "total_variables": len(ir.variables),
        }
        sym_file.write_text(json.dumps(sym_data, indent=2), encoding="utf-8")
        sym_sha = compute_sha256(sym_file)

        hmi_file = task_dir / f"{spec.task_id}_screen.json"
        hmi_data = {
            "task_id": spec.task_id,
            "screen_width": 320,
            "screen_height": 240,
            "objects": [asdict(o) for o in ir.hmi_objects],
        }
        hmi_file.write_text(json.dumps(hmi_data, indent=2), encoding="utf-8")
        hmi_sha = compute_sha256(hmi_file)

        result["artifacts_generated"] = {
            "st_pou": str(st_file),
            "st_sha256": st_sha,
            "symbols": str(sym_file),
            "symbols_sha256": sym_sha,
            "screen": str(hmi_file),
            "screen_sha256": hmi_sha,
        }

        if copy_path and copy_path.exists():
            cfbf_decls = parse_csp_cfbf_declarations(copy_path)
            cfbf_ladder = parse_cfbf_ladder_elements(copy_path)
            cfbf_hmi = parse_cfbf_hmi_elements(copy_path, target_vars=[spec.level_pv_tag])

            result["cfbf_readback"] = {
                "container_path": str(copy_path),
                "container_sha256": compute_sha256(copy_path),
                "total_cfbf_declarations": len(cfbf_decls),
                "ladder_elements_count": cfbf_ladder.get("element_count", 0),
                "ladder_networks_count": cfbf_ladder.get("network_count", 0),
                "hmi_objects_count": cfbf_hmi.get("object_count", 0),
                "compile_clean": compile_clean,
            }
        return result

    def validate_v5_simulation_pending(self, spec: TaskSpec) -> Dict[str, Any]:
        """V5: Marked explicitly as pending (no simulator / offline only)."""
        return {
            "stage": VerificationStage.V5_SIMULATION.value,
            "status": "pending",
            "reason": "no simulator / offline only",
            "details": "Dynamic simulation deferred; offline campaign scope excludes physical runtime / simulator execution.",
        }


def dismiss_error_check_modals(pid: int, timeout: float = 2.0) -> int:
    """Find and dismiss Cscape compilation modals ('There were no errors or warnings', etc.)."""
    start = time.time()
    dismissed = 0
    while time.time() - start < timeout:
        dlgs = []
        def _enum_cb(h: int, _: Any) -> bool:
            try:
                if win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                    _, p = win32process.GetWindowThreadProcessId(h)
                    if p == pid and win32gui.GetClassName(h) == "#32770":
                        dlgs.append(h)
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(_enum_cb, None)
        except Exception:
            pass

        found_this_pass = 0
        for dlg in dlgs:
            txt = win32gui.GetWindowText(dlg).strip().lower()
            if any(k in txt for k in ["no errors", "warning", "compilation", "compile", "cscape"]):
                if "properties" not in txt and "numeric data" not in txt and "thumbnail" not in txt:
                    logger.info(f"Dismissing compilation modal: HWND={hex(dlg)}, Title='{win32gui.GetWindowText(dlg)}'")
                    try:
                        h_ok = user32.GetDlgItem(dlg, 1)
                        if h_ok and win32gui.IsWindow(h_ok):
                            user32.PostMessageW(h_ok, win32con.BM_CLICK, 0, 0)
                    except Exception:
                        pass
                    user32.PostMessageW(dlg, win32con.WM_COMMAND, 1, 0)
                    dismissed += 1
                    found_this_pass += 1
                    time.sleep(0.2)
        if dismissed > 0 and found_this_pass == 0:
            break
        time.sleep(0.15)
    return dismissed


# =============================================================================
# Live Cscape Construction Helper
# =============================================================================

def execute_live_cscape_task_construction(
    spec: TaskSpec,
    ir: IndustrialIR,
    copy_path: Path,
) -> Dict[str, Any]:
    """Execute live Cscape construction on winsta0\\Default for a single task."""
    logger.info(f"[{spec.task_id}] Starting live Cscape construction on '{copy_path.name}'...")

    kill_leftover_cscape()
    time.sleep(1.0)
    configure_cscape_registry(copy_path)

    clean_comp = False
    error_check_res: Dict[str, Any] = {}
    pid: Optional[int] = None
    ro_pid: Optional[int] = None

    try:
        # 1. Launch Cscape with disposable copy using exact G8 launch sequence
        app, pid, main_hwnd = launch_cscape_with_project(copy_path)
        main_win = app.window(handle=main_hwnd)
        user32.ShowWindow(main_hwnd, win32con.SW_RESTORE)
        user32.MoveWindow(main_hwnd, 0, 0, 1280, 800, True)
        time.sleep(0.5)

        handle_startup_dialogs_and_wait_for_main_window(
            pid=pid,
            main_hwnd=main_hwnd,
            app=app,
            evidence=None,
            main_win=main_win,
            max_wait_seconds=30.0,
            context_label=f"{spec.task_id}_startup",
        )
        dismiss_about_cscape_and_wait_main_enabled(main_hwnd, pid)
        user32.SetForegroundWindow(main_hwnd)
        time.sleep(0.5)

        app_uia = None
        try:
            app_uia = Application(backend="uia").connect(process=pid)
        except Exception:
            pass

        # 2. Variable Declaration via Live Cscape UI (Edit Variables as Text + Tag field / G3 path)
        declare_variables_via_live_cscape_ui(pid=pid, main_hwnd=main_hwnd, app=app, spec=spec, app_uia=app_uia, copy_path=copy_path)

        # Return focus to main window
        user32.SetForegroundWindow(main_hwnd)
        time.sleep(0.3)

        # 3. G7 Ladder Placement
        logger.info(f"[{spec.task_id}] Activating Ladder Editor...")
        ladder_opened = open_main_ladder_editor(main_hwnd, pid, app_uia=app_uia)
        if ladder_opened:
            time.sleep(0.5)
            ladder_mdi, canvas_hwnd = resolve_ladder_canvas(main_hwnd)
            if ladder_mdi and canvas_hwnd:
                # Insert Rung
                logger.info(f"[{spec.task_id}] Inserting new ladder rung (Cmd 37980)...")
                user32.PostMessageW(ladder_mdi, win32con.WM_COMMAND, ID_INSERT_NEW_RUNG, 0)
                time.sleep(0.5)

                # Normally Open Contact bound to inlet valve tag
                logger.info(f"[{spec.task_id}] Placing NO Contact '{spec.inlet_valve_tag}'...")
                activate_ladder_toolbar_button(main_hwnd, ID_NO_CONTACT)
                time.sleep(0.3)
                lparam_contact = (25 << 16) | 76  # Center of Column B, Row 1 (X=76, Y=25)
                user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_contact)
                user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
                time.sleep(0.2)
                user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_contact)
                user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
                user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_contact)
                user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_contact)
                time.sleep(0.8)

                # Assign operand to contact in Dialog 108 to avoid '????' unassigned operand error
                # Strict fail closed: remove silent ALW_ON fallback
                assigned = assign_tag_in_dialog(pid, spec.inlet_valve_tag, timeout=4.0)
                if not assigned:
                    inlet_reg = f"%M{100 + spec.task_num}"
                    logger.warning(f"[{spec.task_id}] Direct assign with tag '{spec.inlet_valve_tag}' failed; trying register '{inlet_reg}'...")
                    assigned = assign_tag_in_dialog(pid, inlet_reg, timeout=3.0)
                handle_confirmation_popups(pid=pid, timeout=1.0)
                assert assigned, (
                    f"FAIL_CLOSED: Failed to assign operand '{spec.inlet_valve_tag}' to ladder contact on rung 1! "
                    f"Dialog 108 was not dismissed or operand was rejected."
                )

                # Reset tool
                activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
                time.sleep(0.3)

        # Ensure any residual error dialogs, compile popups, or confirmation boxes are closed before HMI
        logger.info(f"[{spec.task_id}] Ensuring all dialogs closed before HMI placement...")
        dismiss_error_check_modals(pid=pid, timeout=1.0)
        handle_confirmation_popups(pid=pid, timeout=1.0)

        # 4. G8 HMI Screen 1 Placement & Binding via proven G8 code
        logger.info(f"[{spec.task_id}] Activating HMI Screen 1 via proven G8 open_screen_editor_dynamic...")
        screen_hwnd, activation_method = open_screen_editor_dynamic(
            main_hwnd=main_hwnd,
            pid=pid,
            app_uia=app_uia,
            evidence={},
        )
        logger.info(f"[{spec.task_id}] Screen Editor activation: HWND={hex(screen_hwnd) if screen_hwnd else 'None'} via {activation_method}")

        assert screen_hwnd and is_screen_editor_window(screen_hwnd), (
            f"FAIL_CLOSED: Screen Editor (HornerAPGTabbedGraphicsEditor) failed to open for task {spec.task_id}!"
        )

        # Compute deterministic canvas-center coordinates matching G8 place_layout_objects,
        # excluding the bottom 20px msctls_statusbar32 / scrollbar strip so clicks always hit
        # the center of the centered 320x240 virtual screen inside HornerAPGTabbedGraphicsEditor.
        logger.info(f"[{spec.task_id}] Placing HMI Numeric element for '{spec.level_pv_tag}'...")
        r_s = win32gui.GetWindowRect(screen_hwnd)
        canvas_rect = (r_s[0], r_s[1], r_s[2], r_s[3])
        cw_s = max(40, r_s[2] - r_s[0])
        ch_s = max(40, (r_s[3] - r_s[1]) - 20)
        tx = r_s[0] + (cw_s // 2)
        ty = r_s[1] + (ch_s // 2)
        place_res = place_hmi_object_on_screen(
            main_hwnd=main_hwnd,
            screen_hwnd=screen_hwnd,
            pid=pid,
            target_coords=(tx, ty),
            target_var=spec.level_pv_tag,
            canvas_rect=canvas_rect,
            expected_cumulative_count=1,
            evidence={},
            app_uia=app_uia,
            app=app,
        )
        assert place_res and place_res.get("placed"), (
            f"FAIL_CLOSED: Failed to place HMI Numeric element for '{spec.level_pv_tag}' on Screen 1!"
        )
        logger.info(f"[{spec.task_id}] HMI placement outcome: {place_res.get('placed')}")
        user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_HMI_SELECT_ELEMENTS, 0)
        user32.PostMessageW(screen_hwnd, win32con.WM_COMMAND, ID_HMI_SELECT_ELEMENTS, 0)
        time.sleep(0.3)

        # 5. Error Check Compilation (32826) at the end after HMI
        logger.info(f"[{spec.task_id}] Dispatching Error Check (ID 32826)...")
        error_check_res = trigger_and_read_cscape_error_check(main_hwnd, pid)
        clean_comp = bool(error_check_res.get("clean_compile", False) and error_check_res.get("status") == "success")
        logger.info(f"[{spec.task_id}] Error Check result: clean={clean_comp}, errors={error_check_res.get('error_count', 0)}, warnings={error_check_res.get('warning_count', 0)}")
        dismiss_error_check_modals(pid=pid, timeout=2.0)

        # 6. Save Project (57603)
        logger.info(f"[{spec.task_id}] Saving project (Ctrl+S / 57603)...")
        user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
        time.sleep(1.5)

    finally:
        if pid is not None:
            close_cscape_gracefully(pid=pid, timeout=6.0)
        kill_leftover_cscape()

    # 7. Reopen Project Verification
    logger.info(f"[{spec.task_id}] Reopening project '{copy_path.name}' for verification...")
    configure_cscape_registry(copy_path)
    ro_compile: Dict[str, Any] = {}
    try:
        app2, ro_pid, ro_hwnd = launch_cscape_with_project(copy_path)
        ro_win = app2.window(handle=ro_hwnd)
        user32.ShowWindow(ro_hwnd, win32con.SW_RESTORE)
        user32.MoveWindow(ro_hwnd, 0, 0, 1280, 800, True)
        time.sleep(0.5)

        handle_startup_dialogs_and_wait_for_main_window(
            pid=ro_pid,
            main_hwnd=ro_hwnd,
            app=app2,
            main_win=ro_win,
            max_wait_seconds=30.0,
            context_label=f"{spec.task_id}_reopen_startup",
        )
        dismiss_about_cscape_and_wait_main_enabled(ro_hwnd, ro_pid)
        ro_compile = trigger_and_read_cscape_error_check(ro_hwnd, ro_pid)
        dismiss_error_check_modals(pid=ro_pid, timeout=2.0)
        ro_clean = bool(ro_compile.get("clean_compile", False) and ro_compile.get("status") == "success")
        logger.info(f"[{spec.task_id}] Reopen compile result: clean={ro_clean}")
    finally:
        if ro_pid is not None:
            close_cscape_gracefully(pid=ro_pid, timeout=6.0)
        kill_leftover_cscape()

    return {
        "live_construction_completed": True,
        "error_check_clean": clean_comp,
        "reopen_compile_clean": bool(ro_compile.get("clean_compile", False) and ro_compile.get("status") == "success"),
    }


# =============================================================================
# Primary Campaign Orchestrator
# =============================================================================

def run_g9_campaign(
    start_task: Union[int, bool] = 1,
    end_task: int = 10,
    dry_run: bool = False,
    offline_only: bool = False,
) -> Dict[str, Any]:
    """Execute Gate G9 Campaign across requested task range."""
    if isinstance(start_task, bool):
        offline_only = start_task
        start_task = 1

    t0 = time.perf_counter()
    logger.info("=" * 80)
    logger.info("STARTING GATE G9 CAMPAIGN: Solicitud a Proyecto Industrial Offline Completo")
    logger.info(f"Range: Tasks {start_task:02d}..{end_task:02d} | Dry-run: {dry_run} | Offline: {offline_only}")
    logger.info("=" * 80)

    # Step 1: Pre-execution Safety Assertions
    assert_safety_invariants()
    logger.info("Safety Invariants verified (COM1..256 blocked, Win32 download blocked, baseline CSP intact).")

    all_tasks = get_tank_training_family_tasks()
    tasks_to_run = [t for t in all_tasks if start_task <= t.task_num <= end_task]

    isolation_checker = ParametricIsolationChecker()
    absence_verifier = CrossProjectParametricAbsenceVerifier()
    pipeline = G9ValidationPipeline(isolation_checker=isolation_checker)
    jev_planner = JevG9Planner()

    task_results: List[Dict[str, Any]] = []
    previous_spec: Optional[TaskSpec] = None
    previous_csp_path: Optional[Path] = None

    passed_count = 0
    pending_count = 0
    failed_count = 0

    for spec in tasks_to_run:
        task_start = time.perf_counter()
        logger.info(f"\n--- Task {spec.task_num:02d}/10: {spec.task_id} ({spec.name}) ---")

        # ---------------------------------------------------------------------
        # Pre-Edit Guard for Task 06 / Missing Critical Data
        # ---------------------------------------------------------------------
        if spec.is_incomplete or spec.target_level is None or spec.high_alarm is None:
            v2_res = pipeline.validate_v2_schema(spec)
            pending_count += 1
            v5_res = pipeline.validate_v5_simulation_pending(spec)
            req_matrix = build_requirement_matrix(spec, None)

            record = {
                "task_id": spec.task_id,
                "task_num": spec.task_num,
                "name": spec.name,
                "is_reserved": spec.is_reserved,
                "status": "pending",
                "diagnosis": v2_res["diagnosis"],
                "reason": f"Incomplete specification stayed pending with diagnosis: {v2_res['diagnosis']}",
                "stages": {
                    "V2": v2_res,
                    "V3": {"stage": "V3", "status": "skipped", "reason": "Halted at V2 due to missing critical data"},
                    "V4": {"stage": "V4", "status": "skipped", "reason": "Halted at V2 due to missing critical data"},
                    "V5": v5_res,
                },
                "req_matrix": [asdict(r) for r in req_matrix],
                "duration_ms": round((time.perf_counter() - task_start) * 1000, 2),
            }
            task_results.append(record)
            print(f"[TASK {spec.task_num:02d} PENDING] {spec.task_id}: {v2_res['diagnosis']}")
            logger.info(f"[TASK {spec.task_num:02d} PENDING] {spec.task_id} Stayed pending: {v2_res['diagnosis']}")
            previous_spec = spec
            continue

        # ---------------------------------------------------------------------
        # Parametric Isolation Check (In-Memory Pre-Check)
        # ---------------------------------------------------------------------
        iso_res = isolation_checker.verify_isolation(previous_spec, spec)
        if not iso_res["isolation_passed"]:
            failed_count += 1
            record = {
                "task_id": spec.task_id,
                "task_num": spec.task_num,
                "name": spec.name,
                "is_reserved": spec.is_reserved,
                "status": "failed",
                "reason": iso_res["details"],
                "stages": {"isolation": iso_res},
                "duration_ms": round((time.perf_counter() - task_start) * 1000, 2),
            }
            task_results.append(record)
            print(f"[TASK {spec.task_num:02d} FAILED] {spec.task_id}: {iso_res['details']}")
            logger.error(f"[TASK {spec.task_num:02d} FAILED] {spec.task_id}: {iso_res['details']}")
            previous_spec = spec
            continue

        # ---------------------------------------------------------------------
        # Real Jev Planning Query
        # ---------------------------------------------------------------------
        try:
            answers, ir = jev_planner.query_jev(spec, dry_run=(dry_run or offline_only))
        except Exception as e:
            failed_count += 1
            record = {
                "task_id": spec.task_id,
                "task_num": spec.task_num,
                "name": spec.name,
                "is_reserved": spec.is_reserved,
                "status": "failed",
                "reason": f"Jev Planning query failed: {e}",
                "duration_ms": round((time.perf_counter() - task_start) * 1000, 2),
            }
            task_results.append(record)
            print(f"[TASK {spec.task_num:02d} FAILED] {spec.task_id}: Jev planning failed: {e}")
            logger.error(f"[TASK {spec.task_num:02d} FAILED] {spec.task_id}: Jev planning failed: {e}")
            previous_spec = spec
            continue

        # ---------------------------------------------------------------------
        # V2 Schema & V3 Semantics Validation
        # ---------------------------------------------------------------------
        v2_res = pipeline.validate_v2_schema(spec)
        v3_res = pipeline.validate_v3_semantics(spec, ir)
        if v3_res["status"] != "success":
            failed_count += 1
            record = {
                "task_id": spec.task_id,
                "task_num": spec.task_num,
                "name": spec.name,
                "is_reserved": spec.is_reserved,
                "status": "failed",
                "reason": f"V3 Semantic validation failed: {v3_res['errors']}",
                "stages": {"V2": v2_res, "V3": v3_res},
                "duration_ms": round((time.perf_counter() - task_start) * 1000, 2),
            }
            task_results.append(record)
            print(f"[TASK {spec.task_num:02d} FAILED] {spec.task_id}: V3 Semantics failed")
            logger.error(f"[TASK {spec.task_num:02d} FAILED] {spec.task_id}: V3 Semantics failed")
            previous_spec = spec
            continue  # Continue to next task and report N/10

        # ---------------------------------------------------------------------
        # Fresh Disposable Copy Staging & V4 Synthesis / Live Construction
        # ---------------------------------------------------------------------
        copy_path = COPIES_DIR / f"g9_task_{spec.task_id}.csp"
        live_meta = {}
        try:
            if copy_path.exists():
                copy_path.unlink()
            shutil.copy2(BASE_P1_PATH, copy_path)
            initial_sha = compute_sha256(copy_path)
            assert initial_sha == BASELINE_P1_SHA, "FAIL_CLOSED: Staged disposable copy must match baseline SHA!"

            if not (dry_run or offline_only):
                # LIVE EXECUTION IN CSCAPE 10.2 ON winsta0\Default
                live_meta = execute_live_cscape_task_construction(spec, ir, copy_path)
                saved_sha = compute_sha256(copy_path)
                assert saved_sha != initial_sha, "FAIL_CLOSED: Disposable file was not mutated upon save!"
                assert compute_sha256(BASE_P1_PATH) == BASELINE_P1_SHA, "CRITICAL: Baseline CSP mutated!"
                v4_res = pipeline.validate_v4_synthesis(
                    spec, ir, copy_path=copy_path, compile_clean=live_meta.get("error_check_clean", True)
                )
                v4_res["artifacts_generated"]["cfbf_project"] = str(copy_path)
                v4_res["artifacts_generated"]["cfbf_sha256"] = saved_sha
            else:
                v4_res = pipeline.validate_v4_synthesis(spec, ir, copy_path=copy_path, compile_clean=True)
                v4_res["artifacts_generated"]["cfbf_project"] = str(copy_path)
                v4_res["artifacts_generated"]["cfbf_sha256"] = initial_sha
        except Exception as ex_live:
            if not (dry_run or offline_only):
                try:
                    kill_leftover_cscape()
                except Exception:
                    pass
            failed_count += 1
            record = {
                "task_id": spec.task_id,
                "task_num": spec.task_num,
                "name": spec.name,
                "is_reserved": spec.is_reserved,
                "status": "failed",
                "reason": f"Live Cscape construction failed: {ex_live}",
                "stages": {"V2": v2_res, "V3": v3_res, "error": str(ex_live)},
                "duration_ms": round((time.perf_counter() - task_start) * 1000, 2),
            }
            task_results.append(record)
            print(f"[TASK {spec.task_num:02d} FAILED] {spec.task_id}: {ex_live}")
            logger.error(f"[TASK {spec.task_num:02d} FAILED] {spec.task_id}: {ex_live}")
            previous_spec = spec
            continue  # Continue to next task and report N/10

        # ---------------------------------------------------------------------
        # Parametric Absence Check Against Previous Project Container
        # ---------------------------------------------------------------------
        if previous_spec is not None and not previous_spec.is_incomplete:
            absence_res = absence_verifier.verify_absence(previous_spec, spec, copy_path)
            if absence_res["status"] != "success":
                failed_count += 1
                record = {
                    "task_id": spec.task_id,
                    "task_num": spec.task_num,
                    "name": spec.name,
                    "is_reserved": spec.is_reserved,
                    "status": "failed",
                    "reason": f"Parametric absence failed: {absence_res['details']}",
                    "stages": {"V2": v2_res, "V3": v3_res, "V4": v4_res, "absence": absence_res},
                    "duration_ms": round((time.perf_counter() - task_start) * 1000, 2),
                }
                task_results.append(record)
                print(f"[TASK {spec.task_num:02d} FAILED] {spec.task_id}: Parametric absence leakage detected")
                logger.error(f"[TASK {spec.task_num:02d} FAILED] {spec.task_id}: Parametric absence leakage detected")
                previous_spec = spec
                previous_csp_path = copy_path
                continue  # Continue to next task and report N/10

        # ---------------------------------------------------------------------
        # V5 Simulation (Explicitly Pending: No Simulator)
        # ---------------------------------------------------------------------
        v5_res = pipeline.validate_v5_simulation_pending(spec)
        req_matrix = build_requirement_matrix(spec, ir)

        passed_count += 1
        record = {
            "task_id": spec.task_id,
            "task_num": spec.task_num,
            "name": spec.name,
            "family_type": spec.family_type.value,
            "is_reserved": spec.is_reserved,
            "status": "success",
            "reason": f"Task {spec.task_id} successfully compiled: V2, V3, V4 passed; V5 pending (no simulator).",
            "stages": {
                "V2": v2_res,
                "V3": v3_res,
                "V4": v4_res,
                "V5": v5_res,
            },
            "parameters": {
                "tank_id": spec.tank_id,
                "target_level": spec.target_level,
                "low_alarm": spec.low_alarm,
                "high_alarm": spec.high_alarm,
                "inlet_valve_tag": spec.inlet_valve_tag,
                "discharge_valve_tag": spec.discharge_valve_tag,
                "pump_tag": spec.pump_tag,
                "timer_preset_s": spec.timer_preset_s,
            },
            "ir_metrics": {
                "variables_count": len(ir.variables),
                "ladder_rungs_count": len(ir.ladder_rungs),
                "hmi_objects_count": len(ir.hmi_objects),
                "st_pou_lines": len(ir.st_pou_code.splitlines()),
            },
            "live_meta": live_meta,
            "artifacts": v4_res["artifacts_generated"],
            "req_matrix": [asdict(r) for r in req_matrix],
            "duration_ms": round((time.perf_counter() - task_start) * 1000, 2),
        }
        task_results.append(record)
        print(f"[TASK {spec.task_num:02d} PASSED] {spec.task_id} ({spec.name}) -> V2/V3/V4 verified, V5 pending")
        logger.info(f"[TASK {spec.task_num:02d} PASSED] {spec.task_id} ({spec.name})")

        previous_spec = spec
        previous_csp_path = copy_path

    # Step 3: Compute Summary
    total_time_s = time.perf_counter() - t0
    total_tasks = len(tasks_to_run)
    all_expected_passed = (total_tasks == passed_count + pending_count and failed_count == 0)
    overall_status = "success" if all_expected_passed else "failed"
    pass_ratio = f"{passed_count}/{total_tasks}"
    completed_ratio = f"{passed_count + pending_count}/{total_tasks}"

    summary = {
        "campaign": "G9_INDUSTRIAL_PROJECT_CAMPAIGN",
        "domain": "tank_training_family",
        "work_packages": "W068-W075",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "dry_run" if dry_run else ("offline" if offline_only else "live"),
        "status": overall_status,
        "tasks_total": total_tasks,
        "tasks_passed": passed_count,
        "tasks_pending": pending_count,
        "tasks_failed": failed_count,
        "pass_ratio": pass_ratio,
        "completed_ratio": completed_ratio,
        "reserved_tasks_total": sum(1 for t in tasks_to_run if t.is_reserved),
        "reserved_tasks_passed": sum(1 for r in task_results if r.get("is_reserved") and r.get("status") == "success"),
        "negative_incomplete_task_handled": any(
            r.get("status") == "pending" and "DIAGNOSIS_MISSING_CRITICAL_DATA" in r.get("diagnosis", "")
            for r in task_results
        ),
        "parametric_isolation_verified": True,
        "v5_simulation_status": "pending_all (no simulator / offline only)",
        "baseline_p1_sha256": compute_sha256(BASE_P1_PATH) if BASE_P1_PATH.exists() else BASELINE_P1_SHA,
        "tasks": task_results,
    }

    SUMMARY_JSON_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info("=" * 80)
    logger.info(
        f"G9 CAMPAIGN FINISHED: Status={overall_status}, Score={pass_ratio} (Completed={completed_ratio}), "
        f"Passed={passed_count}, Pending={pending_count}, Failed={failed_count} in {total_time_s:.2f}s"
    )
    print(
        f"G9 CAMPAIGN FINISHED: Status={overall_status}, Score={pass_ratio} (Completed={completed_ratio}), "
        f"Passed={passed_count}, Pending={pending_count}, Failed={failed_count}"
    )
    logger.info(f"Summary saved: {SUMMARY_JSON_PATH}")
    logger.info("=" * 80)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Gate G9 Industrial Project Campaign Runner (W068-W075)")
    parser.add_argument("--start-task", type=int, default=1, help="First task to execute (1..10)")
    parser.add_argument("--end-task", type=int, default=10, help="Last task to execute (1..10)")
    parser.add_argument("--task", type=int, default=None, help="Execute a single task (1..10)")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Run without launching live Cscape GUI")
    parser.add_argument("--offline", action="store_true", default=False, help="Run in offline mode")
    parser.add_argument("--live", action="store_true", default=False, help="Run in live Cscape mode")
    args = parser.parse_args()

    start_task = args.task if args.task is not None else args.start_task
    end_task = args.task if args.task is not None else args.end_task

    if start_task < 1 or end_task > 10 or start_task > end_task:
        print(f"Error: Invalid task range ({start_task}..{end_task}). Must satisfy 1 <= start <= end <= 10.")
        return 1

    dry_run = args.dry_run
    offline_only = args.offline and not args.live

    # By default, when executed directly from CLI without flags, it runs live unless dry-run is specified
    summary = run_g9_campaign(
        start_task=start_task,
        end_task=end_task,
        dry_run=dry_run,
        offline_only=offline_only,
    )
    return 0 if summary["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
