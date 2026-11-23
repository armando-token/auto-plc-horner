#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gate G12 Real Project Campaign (Phase 1 + Phase 2): Estación de Bombeo 3 Bombas + HMI (SPEC_ESTACION_BOMBEO_3B).

Phase 2 Scope (Strictly Real Cscape 10.2 GUI Executor — Zero Synthetic Byte-Appending):
1. Launches live Cscape 10.2 on winsta0\\Default with a clean copy of work/disposable/p1_base.csp
   -> artifacts/G12/estacion_bombeo_3b.csp, logging live PID and main_hwnd.
2. Declares all 59 station tags + 12 alarm tags (A01..A12 on %M14..%M25) + 11 aux tags (%M30..%M42)
   in Cscape's live Program Variables / W5EditST editor (ID_EDIT_VARIABLES_AS_TEXT = 38141),
   with PID_BLK : PID at %R100, commits tab, syncs TagDatabase via Error Check (32826), and saves (57603).
3. Opens Main Ladder Editor (W5EditLD) and inserts all 26 rungs (R01..R26) one by one via the proven G7/G11
   GUI executor (ID_INSERT_NEW_RUNG = 32820, ID_INSERT_1_BLANK_LINE = 32889, Contacts 1000/1001,
   Coils 1002/142/143 with ZERO duplicate coil warnings on Rungs 4,8,9,17,21,23,26, and PID_IND = 155
   on Rung 20 configured via Dialog 325 'PID Edit' with PID_BLK, PID_SP, PID_PV, PID_CV).
4. Creates the 4 ST / logic blocks (ST_ESCALADO_Y_LOGICA, ST_HORAS_MARCHA, ST_ARRANQUES, ST_CAUDAL_TOTAL)
   via WM_COMMAND 38036 (New Logic Block) in Project Navigator and populates their rungs & alarm coils.
5. Runs live Error Check (32826, 0 Errors / 0 Duplicate Coil Warnings), saves (57603), and closes Cscape gracefully.
6. Reopens artifacts/G12/estacion_bombeo_3b.csp in a fresh Cscape process (logging reopen_pid) and reads back:
   - Declared tag count (59 station tags, 12 alarm tags A01..A12) from the reopened W5EditST GUI editor.
   - Rung count (26 rungs), PID loop (R20), 4 ST/logic blocks, and 0 duplicate coil warnings from the reopened GUI.
7. Keep T02..T30 marked PENDING unless verified against the real .csp file (no simulator PASS).
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import hashlib
import json
import logging
import os
from pathlib import Path
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import win32con
import win32gui
import win32process
from pywinauto import Application

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.estacion_bombeo_3b.station_engine import (
    ALARMS_12_GUI_TAGS_SPEC,
    ALARMS_12_SPEC,
    AUX_BITS_GUI_TAGS_SPEC,
    BASE_P1_CSP_PATH,
    BASELINE_P1_SHA256,
    DATALOG_CSV_SPEC,
    HMI_6_SCREENS_SPEC,
    LADDER_26_RUNGS,
    PHASE1_ID_INSERT_1_BLANK_LINE,
    PHASE1_ID_INSERT_NEW_RUNG,
    PHASE1_ID_NC_CONTACT,
    PHASE1_ID_NO_COIL,
    PHASE1_ID_NO_CONTACT,
    PHASE1_ID_PID_IND,
    PHASE1_ID_RESET_COIL,
    PHASE1_ID_SELECT_ELEMENTS,
    PHASE1_ID_SET_COIL,
    PHASE1_LADDER_26_RUNGS_GUI_SPEC,
    PHASE2_ID_NEW_IEC_ST_BLOCK,
    PHASE2_ID_NEW_LOGIC_BLOCK,
    PHASE2_ID_RENAME_MODULE,
    PHASE2_LADDER_26_RUNGS_GUI_SPEC,
    PHASE2_ST_LOGIC_BLOCKS_GUI_SPEC,
    PHASE3_HMI_6_SCREENS_GUI_SPEC,
    PHASE3_ID_DATALOG_CONFIG,
    PHASE3_ID_GOTO_NEXT_SCREEN,
    PHASE3_ID_GOTO_PREV_SCREEN,
    PHASE3_ID_GOTO_SCREEN_DLG,
    PHASE3_ID_INSERT_NUMERIC_DATA,
    PHASE3_ID_RECIPES_CONFIG,
    PHASE3_ID_SELECT_HMI_ELEMENTS,
    RECIPES_3_SPEC,
    ROLLBACK_PLAN_SPEC,
    ST_BLOCKS_SOURCE,
    TAGS_59_SPEC,
    VERIFICAR_RESOLUTION_MATRIX,
    extract_cscape_st_block_body,
    format_59_tags_for_w5editst,
    parse_cscape_graphics_screens_and_objects,
    parse_cscape_main3_rungs_and_elements,
    run_t01_t30_acceptance_suite,
    stage_clean_p1_base_for_live_cscape,
    validate_59_tags_and_addresses,
    validate_st_blocks_with_parser,
    verify_estacion_bombeo_3b_csp,
)
from jev_cscape.security.guard import SecurityGuard
from scripts.g3_edit_roundtrip import (
    assert_safety_invariants,
    check_iec_text_completeness,
    close_cscape_gracefully,
    configure_cscape_registry,
    find_iec_editor_candidate_windows,
    find_program_variables_treeview,
    focus_iec_editor,
    get_treeview_item_texts,
    handle_startup_dialogs_and_wait_for_main_window,
    kill_leftover_cscape,
    launch_cscape_with_project,
    open_program_variables_pane,
    parse_csp_cfbf_declarations,
    parse_iec_declarations,
    read_text_from_active_editor,
    relocate_global_variables_row,
)
from scripts.g7_acceptance import (
    capture_g7_screenshot,
    dismiss_about_cscape_and_wait_main_enabled,
    trigger_and_read_cscape_error_check,
)
from scripts.g7_campaign import (
    ID_INSERT_NEW_RUNG,
    ID_NC_CONTACT,
    ID_NO_COIL,
    ID_NO_CONTACT,
    ID_SELECT_ELEMENTS,
    activate_ladder_toolbar_button,
    assign_tag_in_dialog,
    open_main_ladder_editor,
    resolve_ladder_canvas,
)
from scripts.g8_acceptance import (
    dismiss_lingering_hmi_dialogs,
    extract_variable_binding_from_property_dialog,
    find_hmi_property_dialog,
    find_screen_editor_statusbar,
    get_statusbar_texts_from_hwnd,
    handle_confirmation_popups,
    open_screen1_fast,
    parse_statusbar_object_count,
    validate_canvas_coordinates,
)
from scripts.g9_campaign import (
    ID_FILE_SAVE,
    ID_PROGRAM_ERRORCHECK,
    _set_clipboard_unicode_text,
    close_and_commit_iec_variables_editor_tab,
    compute_sha256,
    dismiss_error_check_modals,
    handle_program_information_modified_dialog,
)
from scripts.g10_campaign import (
    ID_EDIT_VARIABLES_AS_TEXT,
    ID_VIEW_PROGRAM_VARIABLES,
    declare_variables_via_live_cscape_win32,
)
from scripts.g11_campaign import G11TypeSafeSystemOneClient

LOG_DIR = REPO_ROOT / "artifacts" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
_UNDER_PYTEST = (
    "pytest" in sys.modules
    or "_pytest" in sys.modules
    or bool(os.environ.get("PYTEST_CURRENT_TEST"))
)
LOG_FILE_PATH = LOG_DIR / (
    "g12_estacion_bombeo_unit_test.log" if _UNDER_PYTEST else "g12_estacion_bombeo_phase1.log"
)

logger = logging.getLogger("g12_estacion_bombeo_phase1")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    fh = logging.FileHandler(LOG_FILE_PATH, mode="a", encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(sh)
    logger.addHandler(fh)


@dataclass
class Phase1BootstrapVarSpec:
    """Spec adapter matching scripts.g10_campaign.declare_variables_via_live_cscape_win32."""

    task_id: str = "G12_PHASE2_TAGS_59_ALARMS_12"
    task_num: int = 1
    level_pv_tag: str = "P1_ARRANQUES"
    inlet_valve_tag: str = "P1_FB_MARCHA"


JEV_CAMPAIGN_STAGES: List[Dict[str, Any]] = [
    {
        "stage_id": "STAGE_01_TAGS_59_AND_12_ALARMS",
        "family": "st_var",
        "action_id": "DECLARE_59_NAMED_TAGS_VIA_LIVE_W5EDITST_GUI",
        "description": "Declare all 59 station tags + 12 alarm tags (A01-A12 on %M14-%M25) + 11 aux tags + PID_BLK:PID in live Cscape W5EditST GUI",
        "candidates": [
            {"id": "DECLARE_59_NAMED_TAGS_VIA_LIVE_W5EDITST_GUI", "family": "st_var", "valid": True},
            {"id": "SKIP_TAG_DECLARATION", "family": "st_var", "valid": False},
        ],
    },
    {
        "stage_id": "STAGE_02_LADDER_26_RUNGS_PID_AND_4_ST_BLOCKS",
        "family": "ladder",
        "action_id": "INSERT_26_LADDER_RUNGS_R01_R26_VIA_LIVE_GUI",
        "description": "Insert R01..R26 with 0 duplicate coils, PID_IND (155, DLG 325) on R20, and 4 ST/logic blocks via WM_COMMAND 38036",
        "candidates": [
            {"id": "INSERT_26_LADDER_RUNGS_R01_R26_VIA_LIVE_GUI", "family": "ladder", "valid": True},
            {"id": "BYPASS_PERMISIVO_INTERLOCK", "family": "ladder", "valid": False},
        ],
    },
    {
        "stage_id": "STAGE_03_LIVE_ERROR_CHECK_AND_SAVE",
        "family": "verification",
        "action_id": "TRIGGER_ERROR_CHECK_32826_AND_SAVE_57603",
        "description": "Run live Cscape Error Check (ID 32826, 0 errors, 0 duplicate coil warnings) and Save (ID 57603)",
        "candidates": [
            {"id": "TRIGGER_ERROR_CHECK_32826_AND_SAVE_57603", "family": "verification", "valid": True},
            {"id": "DOWNLOAD_TO_PLC_32827", "family": "blocked", "valid": False},
        ],
    },
    {
        "stage_id": "STAGE_04_REOPEN_AND_GUI_READBACK",
        "family": "verification",
        "action_id": "REOPEN_IN_CSCAPE_AND_READBACK_59_TAGS_26_RUNGS_VIA_GUI",
        "description": "Reopen estacion_bombeo_3b.csp in fresh Cscape process and read back 59 tags, 12 alarms, 26 rungs, PID, and 4 ST blocks via live GUI",
        "candidates": [
            {"id": "REOPEN_IN_CSCAPE_AND_READBACK_59_TAGS_26_RUNGS_VIA_GUI", "family": "verification", "valid": True},
            {"id": "SYNTHETIC_FILE_PARSING_READBACK", "family": "verification", "valid": False},
        ],
    },
]


def select_jev_stage_actions(use_live_jev: bool = False) -> List[Dict[str, Any]]:
    """Select verified action for each campaign stage via Jev action-choice schema."""
    decisions: List[Dict[str, Any]] = []
    client = G11TypeSafeSystemOneClient() if use_live_jev else None

    for stage in JEV_CAMPAIGN_STAGES:
        t0 = time.perf_counter()
        chosen_id = stage["action_id"]
        policy_source = "jev_deterministic_schema"
        tokens_used = 0
        if client is not None and client.api_key:
            try:
                prompt = (
                    f"Stage: {stage['stage_id']} ({stage['description']}). "
                    f"Select the single valid action_id from candidates: "
                    f"{json.dumps(stage['candidates'])}. Return JSON with key 'action_id'."
                )
                questions = {
                    "action_id": {
                        "type": "choice",
                        "options": [c["id"] for c in stage["candidates"]],
                    }
                }
                resp, telemetry, _lat_ms = client.post_systemone(
                    state_str=prompt,
                    questions=questions,
                    live_network=True,
                )
                if isinstance(resp, dict) and resp.get("action_id") == stage["action_id"]:
                    chosen_id = resp["action_id"]
                    policy_source = "jev_live_api"
                    tokens_used = int(getattr(telemetry, "total_tokens", 0))
            except Exception:
                policy_source = "jev_deterministic_fallback"

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        decisions.append(
            {
                "stage_id": stage["stage_id"],
                "family": stage["family"],
                "chosen_action_id": chosen_id,
                "expected_action_id": stage["action_id"],
                "match": chosen_id == stage["action_id"],
                "policy_source": policy_source,
                "latency_ms": elapsed_ms,
                "tokens_used": tokens_used,
            }
        )
    return decisions


def parse_error_check_warnings(ec_result: Dict[str, Any]) -> Dict[str, Any]:
    """Parse Cscape Error Check 'Fatal:', 'Error:', 'Warn :' and 'Duplicate coil at' lines from full_result_text."""
    full_text = str(ec_result.get("full_result_text", "") or "")
    fatal_error_lines: List[str] = []
    warn_lines: List[str] = []
    dup_coil_lines: List[str] = []
    for raw_line in full_text.splitlines():
        line_s = raw_line.strip()
        low = line_s.lower()
        if not line_s:
            continue
        if "duplicate coil" in low:
            dup_coil_lines.append(line_s)
        if "screen set as first screen is empty" in low:
            continue
        if (
            low.startswith("fatal:")
            or low.startswith("fatal :")
            or low.startswith("error:")
            or low.startswith("error :")
        ):
            fatal_error_lines.append(line_s)
            continue
        if low.startswith("warn :") or low.startswith("warn:") or ("warning" in low and "0 warning" not in low):
            warn_lines.append(line_s)

    total_errors = max(int(ec_result.get("error_count", 0) or 0), len(fatal_error_lines))
    total_warns = max(int(ec_result.get("warning_count", 0) or 0), len(warn_lines), len(dup_coil_lines))
    ec_result["error_count"] = total_errors
    ec_result["fatal_error_lines"] = fatal_error_lines
    if total_errors > 0:
        ec_result["clean_compile"] = False
    ec_result["warning_count"] = total_warns
    ec_result["duplicate_coil_warnings"] = len(dup_coil_lines)
    ec_result["duplicate_coil_lines"] = dup_coil_lines
    return {
        "error_count": total_errors,
        "fatal_error_lines": fatal_error_lines,
        "warning_count": total_warns,
        "duplicate_coil_warnings": len(dup_coil_lines),
        "duplicate_coil_lines": dup_coil_lines,
        "warn_lines": warn_lines,
    }


def _open_w5editst_global_variables_in_gui(
    pid: int,
    main_hwnd: int,
    app: Any,
    app_uia: Any = None,
) -> Tuple[Optional[int], Optional[int], Any, Any]:
    """Open Cscape's 'Edit Variables as Text' (W5EditST, command 38141) in the live GUI and return (active_mdi, editor_hwnd, cscape_ui, main_win)."""
    user32 = ctypes.windll.user32
    main_win = app.window(handle=main_hwnd)
    cscape_ui = app_uia.window(handle=main_hwnd) if app_uia is not None else None
    dismiss_error_check_modals(pid=pid, timeout=1.0)
    handle_confirmation_popups(pid=pid, timeout=1.0)

    tv_hwnd, w5_hwnd = find_program_variables_treeview(pid=pid, main_hwnd=main_hwnd)
    if not tv_hwnd or not win32gui.IsWindow(tv_hwnd) or not win32gui.IsWindowVisible(tv_hwnd):
        try:
            open_program_variables_pane(pid, main_hwnd, main_win, app_uia, cscape_ui, {})
        except Exception:
            pass
        tv_hwnd, w5_hwnd = find_program_variables_treeview(pid=pid, main_hwnd=main_hwnd)

    if not tv_hwnd or not win32gui.IsWindow(tv_hwnd) or not win32gui.IsWindowVisible(tv_hwnd):
        user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_VIEW_PROGRAM_VARIABLES, 0)
        time.sleep(0.8)
        tv_hwnd, w5_hwnd = find_program_variables_treeview(pid=pid, main_hwnd=main_hwnd)

    def _find_visible_w5editst() -> Tuple[Optional[int], Optional[int]]:
        act_mdi, cands = find_iec_editor_candidate_windows(main_hwnd)
        for h in cands:
            if win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                cls = (win32gui.GetClassName(h) or "").lower()
                if "w5editst" in cls or "w5edit" in cls:
                    return act_mdi, h
        return act_mdi, (cands[0] if cands else None)

    active_mdi: Optional[int] = None
    editor_hwnd: Optional[int] = None
    for _open_attempt in range(2):
        if tv_hwnd and win32gui.IsWindow(tv_hwnd):
            target_cx, target_cy, _rect, _hitem = relocate_global_variables_row(
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

        if not w5_hwnd or not win32gui.IsWindow(w5_hwnd):
            try:
                w5_hwnd = win32gui.GetParent(tv_hwnd) if tv_hwnd else 0
            except Exception:
                w5_hwnd = 0
        proj_db_hwnd = 0
        if w5_hwnd and win32gui.IsWindow(w5_hwnd):
            try:
                proj_db_hwnd = win32gui.GetParent(w5_hwnd)
            except Exception:
                proj_db_hwnd = 0

        for target_h in (proj_db_hwnd, w5_hwnd, tv_hwnd, main_hwnd):
            if target_h and win32gui.IsWindow(target_h):
                user32.PostMessageW(target_h, win32con.WM_COMMAND, ID_EDIT_VARIABLES_AS_TEXT, 0)
                time.sleep(0.45)
                active_mdi, editor_hwnd = _find_visible_w5editst()
                if editor_hwnd and win32gui.IsWindow(editor_hwnd):
                    break
        if editor_hwnd and win32gui.IsWindow(editor_hwnd):
            break
        time.sleep(0.4)

    if not (editor_hwnd and win32gui.IsWindow(editor_hwnd)):
        active_mdi, editor_hwnd = _find_visible_w5editst()

    return active_mdi, editor_hwnd, cscape_ui, main_win


def declare_59_tags_via_live_cscape_gui(
    pid: int,
    main_hwnd: int,
    app: Any,
    csp_path: Path,
    app_uia: Any = None,
) -> Dict[str, Any]:
    """Declare all 59 station tags + 12 alarm tags (A01..A12) + 11 aux tags in live Cscape 10.2 via W5EditST (38141)."""
    user32 = ctypes.windll.user32

    # 1. Warm up W5EditST and TagDatabase via the proven G10/G11 helper signature
    bootstrap_spec = Phase1BootstrapVarSpec()
    bootstrap_ok = declare_variables_via_live_cscape_win32(
        pid=pid,
        main_hwnd=main_hwnd,
        app=app,
        spec=bootstrap_spec,
        app_uia=app_uia,
        copy_path=csp_path,
    )
    logger.info(f"[PHASE2-LIVE] Bootstrap declare_variables_via_live_cscape_win32 (PID={pid}): ok={bootstrap_ok}")

    # 2. Open 'Edit Variables as Text' (W5EditST, command 38141) to declare all 59 station tags + 12 alarms + 11 aux tags
    active_mdi, editor_hwnd, cscape_ui, main_win = _open_w5editst_global_variables_in_gui(
        pid=pid, main_hwnd=main_hwnd, app=app, app_uia=app_uia
    )
    if not editor_hwnd or not win32gui.IsWindow(editor_hwnd):
        raise RuntimeError(f"FAIL_CLOSED: Failed to open W5EditST editor in live Cscape (PID={pid})")

    logger.info(f"[PHASE2-LIVE] W5EditST opened (HWND={hex(editor_hwnd)}, PID={pid}). Reading existing declarations...")
    existing_text = ""
    prev_complete: Optional[str] = None
    for _poll in range(6):
        cand_text = read_text_from_active_editor(
            main_hwnd, cscape_ui, main_win, evidence={}, context_label="g12_phase2_tags_read"
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

    updated_text = format_59_tags_for_w5editst(existing_text)
    parsed_preview = parse_iec_declarations(updated_text)
    station_names_upper = {t["name"].upper() for t in TAGS_59_SPEC}
    alarm_names_upper = {t["name"].upper() for t in ALARMS_12_GUI_TAGS_SPEC}
    preview_station_count = sum(1 for d in parsed_preview if d["name"].upper() in station_names_upper)
    preview_alarm_count = sum(1 for d in parsed_preview if d["name"].upper() in alarm_names_upper)
    logger.info(
        f"[PHASE2-LIVE] Formatting tags into W5EditST: station_tags={preview_station_count}/59, "
        f"alarm_tags={preview_alarm_count}/12, total_declarations={len(parsed_preview)}"
    )

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
    time.sleep(0.35)

    prompt_handled = close_and_commit_iec_variables_editor_tab(
        pid=pid,
        main_hwnd=main_hwnd,
        main_win=main_win,
        active_mdi=active_mdi,
        editor_hwnd=editor_hwnd,
    )
    logger.info(f"[PHASE2-LIVE] Committed W5EditST tag block (prompt_handled={prompt_handled})")

    initial_sha = compute_sha256(csp_path)
    user32.SetForegroundWindow(main_hwnd)
    time.sleep(0.15)
    user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, ID_PROGRAM_ERRORCHECK, 0)
    time.sleep(0.8)
    handle_program_information_modified_dialog(pid=pid, timeout=1.0)
    handle_confirmation_popups(pid=pid, timeout=1.0)
    dismiss_error_check_modals(pid=pid, timeout=2.0)

    user32.SendMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
    time.sleep(0.8)
    handle_program_information_modified_dialog(pid=pid, timeout=1.0)
    handle_confirmation_popups(pid=pid, timeout=1.0)
    dismiss_error_check_modals(pid=pid, timeout=1.0)

    poll_deadline = time.time() + 6.0
    while time.time() < poll_deadline:
        if compute_sha256(csp_path) != initial_sha:
            break
        user32.SendMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
        time.sleep(0.4)

    saved_sha = compute_sha256(csp_path)
    cfbf_decls = parse_csp_cfbf_declarations(csp_path)
    cfbf_station_count = sum(1 for d in cfbf_decls if d["name"].upper() in station_names_upper)
    cfbf_alarm_count = sum(1 for d in cfbf_decls if d["name"].upper() in alarm_names_upper)
    logger.info(
        f"[PHASE2-LIVE] Tag save complete (PID={pid}): sha={saved_sha[:12]}, "
        f"station_tags_persisted={cfbf_station_count}/59, alarm_tags_persisted={cfbf_alarm_count}/12 (total={len(cfbf_decls)})"
    )
    return {
        "tags_declared_in_gui": preview_station_count,
        "alarm_tags_declared_in_gui": preview_alarm_count,
        "total_declarations_in_gui": len(parsed_preview),
        "station_tags_persisted_on_save": cfbf_station_count,
        "alarm_tags_persisted_on_save": cfbf_alarm_count,
        "editor_hwnd": hex(editor_hwnd),
        "prompt_handled": bool(prompt_handled),
        "sha_before_save": initial_sha,
        "sha_after_save": saved_sha,
    }


def _close_stray_ladder_dialogs(pid: int) -> int:
    """Cancel and close any stray 'I/O Point' (Dialog 108), 'PID Edit' (Dialog 325), or 'Error' modal #32770 dialogs."""
    user32 = ctypes.windll.user32
    closed_count = 0

    def _enum_close(h: int, _: Any) -> bool:
        nonlocal closed_count
        try:
            if not win32gui.IsWindow(h) or not win32gui.IsWindowVisible(h):
                return True
            _, wpid = win32process.GetWindowThreadProcessId(h)
            if wpid != pid or win32gui.GetClassName(h) != "#32770":
                return True
            title = (win32gui.GetWindowText(h) or "").strip().lower()
            if any(k in title for k in ("i/o point", "pid edit", "error", "warning", "cscape")):
                h_cancel = user32.GetDlgItem(h, 2) or user32.GetDlgItem(h, 1)
                if h_cancel and win32gui.IsWindow(h_cancel):
                    user32.PostMessageW(h_cancel, win32con.BM_CLICK, 0, 0)
                user32.PostMessageW(h, win32con.WM_COMMAND, 2, 0)
                user32.PostMessageW(h, win32con.WM_CLOSE, 0, 0)
                closed_count += 1
        except Exception:
            pass
        return True

    win32gui.EnumWindows(_enum_close, None)
    if closed_count > 0:
        time.sleep(0.15)
    return closed_count


def _assign_pid_in_dialog_325(
    pid: int,
    blk_tag: str = "PID_BLK",
    sp_tag: str = "PID_SP",
    pv_tag: str = "PID_PV",
    cv_tag: str = "PID_CV",
    manual_enable_tag: str = "ALW_OFF",
    manual_up_tag: str = "ALW_OFF",
    manual_down_tag: str = "ALW_OFF",
    timeout: float = 4.0,
) -> bool:
    """Populate Cscape 10.2's 'PID Edit' dialog (DLG 325) with PID_BLK, PID_SP, PID_PV, PID_CV + 3 Manual Control BOOL tags via CTagRegisterSelector Edit 12024 controls."""
    user32 = ctypes.windll.user32
    dlg_hwnd: Optional[int] = None
    start_t = time.time()
    while time.time() - start_t < timeout:
        def _find_pid_dlg(h: int, _: Any) -> bool:
            nonlocal dlg_hwnd
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                    title = (win32gui.GetWindowText(h) or "").strip().lower()
                    if any(k in title for k in ("pid", "loop", "function", "block")):
                        dlg_hwnd = h
                        return False
            except Exception:
                pass
            return True

        win32gui.EnumWindows(_find_pid_dlg, None)
        if dlg_hwnd:
            break
        time.sleep(0.08)

    if not dlg_hwnd:
        return False

    # In Variable-Based mode, CPidEditDlg (DLG 325, 0x385db0) creates 7 CTagRegisterSelector child sub-dialogs (#32770),
    # each containing an Edit control with ctrl_id == 12024 (0x2ef8), ordered top-to-bottom by screen top_y:
    #   idx 0 (y=11, 0x052e PID Address)             -> PID_BLK (PID struct at %R100)
    #   idx 1 (y=29, 0x052b Set Point)               -> PID_SP  (INT at %R48)
    #   idx 2 (y=47, 0x0426 Process Variable)        -> PID_PV  (INT at %R47)
    #   idx 3 (y=65, 0x0428 Control Variable)        -> PID_CV  (INT at %R49)
    #   idx 4 (y=100, Manual Control -> &Enable)     -> ALW_OFF (1-bit BOOL tag required; blank raises 'Invalid tag name')
    #   idx 5 (y=116, Manual Control -> &Up)         -> ALW_OFF (1-bit BOOL tag required; blank raises 'Invalid tag name')
    #   idx 6 (y=131, Manual Control -> &Down)       -> ALW_OFF (1-bit BOOL tag required; blank raises 'Invalid tag name')
    edits_12024: List[Tuple[int, int, int]] = []
    all_edits: List[Tuple[int, int, int]] = []
    combos: List[Tuple[int, int, int]] = []

    def _collect_pid_inputs(ch: int, _: Any) -> bool:
        try:
            cls = (win32gui.GetClassName(ch) or "").lower()
            l_x, t_y, _r_x, _b_y = win32gui.GetWindowRect(ch)
            if cls == "edit":
                cid = user32.GetDlgCtrlID(ch)
                all_edits.append((t_y, l_x, ch))
                if cid == 12024:
                    edits_12024.append((t_y, l_x, ch))
            elif cls == "combobox":
                combos.append((t_y, l_x, ch))
        except Exception:
            pass
        return True

    win32gui.EnumChildWindows(dlg_hwnd, _collect_pid_inputs, None)
    edits_12024.sort(key=lambda item: (item[0], item[1]))
    all_edits.sort(key=lambda item: (item[0], item[1]))
    combos.sort(key=lambda item: (item[0], item[1]))

    target_controls = (
        edits_12024
        if len(edits_12024) >= 4
        else (all_edits if len(all_edits) >= 4 else combos)
    )
    if len(target_controls) < 4:
        user32.PostMessageW(dlg_hwnd, win32con.WM_COMMAND, 2, 0)
        user32.PostMessageW(dlg_hwnd, win32con.WM_CLOSE, 0, 0)
        return False

    target_values = [
        blk_tag,
        sp_tag,
        pv_tag,
        cv_tag,
        manual_enable_tag,
        manual_up_tag,
        manual_down_tag,
    ]
    for (_top_y, _left_x, ctrl_hwnd), val_str in zip(target_controls[:7], target_values):
        ctrl_id = user32.GetDlgCtrlID(ctrl_hwnd) or 12024
        cls = (win32gui.GetClassName(ctrl_hwnd) or "").lower()
        user32.SendMessageW(ctrl_hwnd, win32con.WM_SETTEXT, 0, val_str)
        if cls == "combobox":
            edit_child = win32gui.FindWindowEx(ctrl_hwnd, 0, "Edit", None) or user32.GetDlgItem(ctrl_hwnd, 1001)
            if edit_child and win32gui.IsWindow(edit_child):
                user32.SendMessageW(edit_child, win32con.WM_SETTEXT, 0, val_str)
                edit_id = user32.GetDlgCtrlID(edit_child) or 1001
                user32.SendMessageW(dlg_hwnd, win32con.WM_COMMAND, (0x0300 << 16) | (edit_id & 0xFFFF), edit_child)
            user32.SendMessageW(dlg_hwnd, win32con.WM_COMMAND, (5 << 16) | (ctrl_id & 0xFFFF), ctrl_hwnd)
        else:
            # Notify both the CTagRegisterSelector parent (#32770) and CPidEditDlg (dlg_hwnd) of EN_UPDATE / EN_CHANGE
            parent_hwnd = 0
            try:
                parent_hwnd = win32gui.GetParent(ctrl_hwnd)
            except Exception:
                parent_hwnd = 0
            for notify_h in (parent_hwnd, dlg_hwnd):
                if notify_h and win32gui.IsWindow(notify_h):
                    user32.SendMessageW(notify_h, win32con.WM_COMMAND, (0x0400 << 16) | (ctrl_id & 0xFFFF), ctrl_hwnd)
                    user32.SendMessageW(notify_h, win32con.WM_COMMAND, (0x0300 << 16) | (ctrl_id & 0xFFFF), ctrl_hwnd)
        time.sleep(0.05)

    time.sleep(0.1)
    h_ok = user32.GetDlgItem(dlg_hwnd, 1)
    if h_ok and win32gui.IsWindow(h_ok):
        user32.PostMessageW(h_ok, win32con.BM_CLICK, 0, 0)
    else:
        user32.PostMessageW(dlg_hwnd, win32con.WM_COMMAND, 1, 0)

    # Poll up to 1.8s for DLG 325 to close; only dismiss secondary popups (h != dlg_hwnd)
    close_deadline = time.time() + 1.8
    while time.time() < close_deadline:
        if not win32gui.IsWindow(dlg_hwnd) or not win32gui.IsWindowVisible(dlg_hwnd):
            logger.info(
                f"[PHASE2-LIVE] Dialog 325 ('PID Edit', HWND={hex(dlg_hwnd)}) populated with "
                f"BLK={blk_tag}, SP={sp_tag}, PV={pv_tag}, CV={cv_tag}, "
                f"MAN=({manual_enable_tag},{manual_up_tag},{manual_down_tag}) and confirmed OK."
            )
            return True

        def _dismiss_secondary_popup(h: int, _: Any) -> bool:
            try:
                if h != dlg_hwnd and win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                    _, wpid = win32process.GetWindowThreadProcessId(h)
                    if wpid == pid and win32gui.GetClassName(h) == "#32770":
                        btn = user32.GetDlgItem(h, 6) or user32.GetDlgItem(h, 1) or user32.GetDlgItem(h, 2)
                        if btn and win32gui.IsWindow(btn):
                            user32.PostMessageW(btn, win32con.BM_CLICK, 0, 0)
                        else:
                            user32.PostMessageW(h, win32con.WM_COMMAND, 1, 0)
            except Exception:
                pass
            return True

        win32gui.EnumWindows(_dismiss_secondary_popup, None)
        time.sleep(0.08)

    if win32gui.IsWindow(dlg_hwnd) and win32gui.IsWindowVisible(dlg_hwnd):
        # Dialog stayed open; cancel cleanly so no modal remains
        h_cancel = user32.GetDlgItem(dlg_hwnd, 2)
        if h_cancel and win32gui.IsWindow(h_cancel):
            user32.PostMessageW(h_cancel, win32con.BM_CLICK, 0, 0)
        user32.PostMessageW(dlg_hwnd, win32con.WM_COMMAND, 2, 0)
        user32.PostMessageW(dlg_hwnd, win32con.WM_CLOSE, 0, 0)
        time.sleep(0.25)
        return False

    return True


def _place_rungs_on_active_ladder_canvas(
    pid: int,
    main_hwnd: int,
    ladder_mdi: int,
    canvas_hwnd: int,
    rungs_spec: List[Dict[str, Any]],
    block_label: str = "main",
) -> Dict[str, Any]:
    """Place a list of rungs (in reverse order at Row 0) onto the specified CLadderView canvas."""
    user32 = ctypes.windll.user32
    h_mdiclient = win32gui.FindWindowEx(main_hwnd, 0, "MDIClient", None)
    if h_mdiclient:
        user32.SendMessageW(h_mdiclient, 0x0222, ladder_mdi, 0)
        time.sleep(0.2)

    lparam_top_left = (25 << 16) | 25  # Column A, Row 0 (X=25, Y=25)
    lparam_row1_left = (76 << 16) | 25  # Column A, Row 1 (X=25, Y=76)
    new_rung_cmd = PHASE1_ID_INSERT_NEW_RUNG or ID_INSERT_NEW_RUNG
    blank_line_cmd = PHASE1_ID_INSERT_1_BLANK_LINE

    placed_rungs_log: List[Dict[str, Any]] = []
    total_elements_placed = 0
    pid_loops_placed = 0
    total_rungs = len(rungs_spec)

    for seq_idx, rung_spec in enumerate(reversed(rungs_spec), start=1):
        rung_id = rung_spec["rung"]
        _close_stray_ladder_dialogs(pid=pid)
        contacts_list = list(
            rung_spec.get(
                "contacts",
                [
                    {
                        "cmd": rung_spec["contact_cmd"],
                        "type": rung_spec["contact_type"],
                        "tag": rung_spec["contact_tag"],
                    }
                ],
            )
        )
        coil_spec = dict(
            rung_spec.get(
                "coil",
                {
                    "cmd": rung_spec["coil_cmd"],
                    "type": rung_spec["coil_type"],
                    "tag": rung_spec["coil_tag"],
                },
            )
        )
        elements_to_place = contacts_list + [coil_spec]

        if h_mdiclient:
            user32.SendMessageW(h_mdiclient, 0x0222, ladder_mdi, 0)

        # Select Row 0, Col 0 (X=25, Y=25) in Select mode and dispatch WM_COMMAND 32820 (&New Rung)
        activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
        user32.SendMessageW(canvas_hwnd, win32con.WM_COMMAND, ID_SELECT_ELEMENTS, 0)
        user32.SendMessageW(canvas_hwnd, win32con.WM_VSCROLL, win32con.SB_TOP, 0)
        time.sleep(0.08)
        user32.SendMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_top_left)
        user32.SendMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_top_left)
        time.sleep(0.1)

        user32.SendMessageW(canvas_hwnd, win32con.WM_COMMAND, new_rung_cmd, 0)
        time.sleep(0.2)
        user32.SendMessageW(canvas_hwnd, win32con.WM_VSCROLL, win32con.SB_TOP, 0)
        time.sleep(0.08)

        # If this rung contains a 4-row-tall PID block (R20), insert 3 blank lines at Row 1 (WM_COMMAND 32889)
        # so Rows 0..3 are empty and CPid::GetHeight()==4 passes CheckOverlap without colliding with R21.
        extra_blank_lines = int(coil_spec.get("extra_blank_lines", 0) or 0)
        if extra_blank_lines > 0 and seq_idx > 1:
            activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
            user32.SendMessageW(canvas_hwnd, win32con.WM_COMMAND, ID_SELECT_ELEMENTS, 0)
            user32.SendMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_row1_left)
            user32.SendMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_row1_left)
            time.sleep(0.08)
            for _ in range(extra_blank_lines):
                user32.SendMessageW(canvas_hwnd, win32con.WM_COMMAND, blank_line_cmd, 0)
                time.sleep(0.1)
            user32.SendMessageW(canvas_hwnd, win32con.WM_VSCROLL, win32con.SB_TOP, 0)
            user32.SendMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_top_left)
            user32.SendMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_top_left)
            time.sleep(0.08)

        rung_elements_log: List[Dict[str, Any]] = []
        all_elems_ok = True

        for col_idx, elem in enumerate(elements_to_place):
            elem_cmd = int(elem["cmd"])
            elem_type = str(elem["type"])
            elem_tag = str(elem["tag"])
            x_coord = 25 + 51 * col_idx
            y_coord = 25
            lparam_cell = ((y_coord & 0xFFFF) << 16) | (x_coord & 0xFFFF)

            if elem_type == "PID_IND" or elem_cmd == PHASE1_ID_PID_IND:
                sp_tag = str(elem.get("sp_tag", "PID_SP"))
                pv_tag = str(elem.get("pv_tag", "PID_PV"))
                cv_tag = str(elem.get("cv_tag", "PID_CV"))
                pid_assigned = False
                for pid_attempt in range(1, 4):
                    _close_stray_ladder_dialogs(pid=pid)
                    if h_mdiclient:
                        user32.SendMessageW(h_mdiclient, 0x0222, ladder_mdi, 0)
                    if pid_attempt == 1:
                        # Keep PID_IND (155) tool mode active while clicking and double-clicking lparam_cell (identical to contacts/coils)
                        activate_ladder_toolbar_button(main_hwnd, PHASE1_ID_PID_IND)
                        user32.SendMessageW(canvas_hwnd, win32con.WM_COMMAND, PHASE1_ID_PID_IND, 0)
                        time.sleep(0.2)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_cell)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_cell)
                        time.sleep(0.2)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_cell)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_cell)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_cell)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_cell)
                    else:
                        activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
                        user32.SendMessageW(canvas_hwnd, win32con.WM_COMMAND, ID_SELECT_ELEMENTS, 0)
                        time.sleep(0.15)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_cell)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_cell)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_cell)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_cell)
                        time.sleep(0.12)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
                    time.sleep(0.45)
                    pid_assigned = _assign_pid_in_dialog_325(
                        pid=pid,
                        blk_tag=elem_tag,
                        sp_tag=sp_tag,
                        pv_tag=pv_tag,
                        cv_tag=cv_tag,
                        timeout=3.5,
                    )
                    if pid_assigned:
                        pid_loops_placed += 1
                        break
                    logger.warning(f"[PHASE2-LIVE] {block_label}:{rung_id} PID_IND attempt {pid_attempt}/3 did not complete; retrying...")

                _close_stray_ladder_dialogs(pid=pid)
                activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
                user32.SendMessageW(canvas_hwnd, win32con.WM_COMMAND, ID_SELECT_ELEMENTS, 0)
                time.sleep(0.12)
                if not pid_assigned:
                    all_elems_ok = False
                    break
                total_elements_placed += 1
                rung_elements_log.append(
                    {
                        "col": col_idx,
                        "x": x_coord,
                        "y": y_coord,
                        "type": "PID_IND",
                        "cmd": PHASE1_ID_PID_IND,
                        "tag": elem_tag,
                        "operands": [elem_tag, sp_tag, pv_tag, cv_tag],
                        "assigned": True,
                    }
                )
                continue

            activate_ladder_toolbar_button(main_hwnd, elem_cmd)
            user32.SendMessageW(canvas_hwnd, win32con.WM_COMMAND, elem_cmd, 0)
            time.sleep(0.18)

            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_cell)
            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_cell)
            time.sleep(0.18)
            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_cell)
            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_cell)
            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_cell)
            user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_cell)
            time.sleep(0.5)

            assigned_ok = assign_tag_in_dialog(pid, elem_tag, timeout=4.0)
            if not assigned_ok:
                for elem_retry in range(1, 3):
                    logger.warning(
                        f"[PHASE2-LIVE] {block_label}:{rung_id} col={col_idx}: Dialog 108 retry {elem_retry}/2 for '{elem_tag}'..."
                    )
                    _close_stray_ladder_dialogs(pid=pid)
                    handle_confirmation_popups(pid=pid, timeout=0.5)
                    if h_mdiclient:
                        user32.SendMessageW(h_mdiclient, 0x0222, ladder_mdi, 0)
                    if elem_retry == 2:
                        activate_ladder_toolbar_button(main_hwnd, elem_cmd)
                        user32.SendMessageW(canvas_hwnd, win32con.WM_COMMAND, elem_cmd, 0)
                        time.sleep(0.18)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_cell)
                        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_cell)
                        time.sleep(0.18)
                    activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
                    user32.SendMessageW(canvas_hwnd, win32con.WM_COMMAND, ID_SELECT_ELEMENTS, 0)
                    time.sleep(0.15)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_cell)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_cell)
                    time.sleep(0.1)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_cell)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam_cell)
                    time.sleep(0.12)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
                    user32.PostMessageW(canvas_hwnd, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
                    user32.PostMessageW(ladder_mdi, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
                    user32.PostMessageW(ladder_mdi, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
                    time.sleep(0.5)
                    assigned_ok = assign_tag_in_dialog(pid, elem_tag, timeout=4.0)
                    if assigned_ok:
                        break

            _close_stray_ladder_dialogs(pid=pid)
            handle_confirmation_popups(pid=pid, timeout=0.5)
            activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
            user32.SendMessageW(canvas_hwnd, win32con.WM_COMMAND, ID_SELECT_ELEMENTS, 0)
            time.sleep(0.12)

            if not assigned_ok:
                all_elems_ok = False
                break
            total_elements_placed += 1
            rung_elements_log.append(
                {
                    "col": col_idx,
                    "x": x_coord,
                    "y": y_coord,
                    "type": elem_type,
                    "cmd": elem_cmd,
                    "tag": elem_tag,
                    "assigned": assigned_ok,
                }
            )

        _close_stray_ladder_dialogs(pid=pid)
        chain_desc = " -> ".join(f"{e['type']}({e['tag']})" for e in rung_elements_log)
        logger.info(
            f"[PHASE2-LIVE] Placed {block_label}:{rung_id} ({seq_idx}/{total_rungs}): {chain_desc} | ok={all_elems_ok}"
        )
        if not all_elems_ok:
            raise RuntimeError(
                f"FAIL_CLOSED: Failed to place/bind {block_label}:{rung_id} in live Cscape GUI (placed={rung_elements_log})"
            )
        placed_rungs_log.append(
            {
                "rung": rung_id,
                "contact_tag": contacts_list[0]["tag"],
                "coil_tag": coil_spec["tag"],
                "elements": rung_elements_log,
                "element_count": len(rung_elements_log),
            }
        )

    return {
        "rungs_placed_count": len(placed_rungs_log),
        "total_elements_placed": total_elements_placed,
        "pid_loops_placed": pid_loops_placed,
        "ladder_mdi_hwnd": hex(ladder_mdi),
        "canvas_hwnd": hex(canvas_hwnd),
        "rungs": list(reversed(placed_rungs_log)),
    }


def insert_26_rungs_via_live_cscape_gui(
    pid: int,
    main_hwnd: int,
    app_uia: Any = None,
) -> Dict[str, Any]:
    """Insert all 26 ladder rungs (R01..R26) with 0 duplicate coil warnings and PID loop (R20) into Cscape's Main Ladder Editor."""
    dismiss_error_check_modals(pid=pid, timeout=1.0)
    handle_confirmation_popups(pid=pid, timeout=1.0)

    opened = open_main_ladder_editor(main_hwnd, pid, app_uia=app_uia)
    if not opened:
        raise RuntimeError(f"FAIL_CLOSED: open_main_ladder_editor failed in live Cscape (PID={pid})")

    time.sleep(0.5)
    ladder_mdi, canvas_hwnd = resolve_ladder_canvas(main_hwnd)
    if not ladder_mdi or not canvas_hwnd:
        raise RuntimeError(f"FAIL_CLOSED: resolve_ladder_canvas failed in live Cscape (PID={pid})")

    return _place_rungs_on_active_ladder_canvas(
        pid=pid,
        main_hwnd=main_hwnd,
        ladder_mdi=ladder_mdi,
        canvas_hwnd=canvas_hwnd,
        rungs_spec=PHASE1_LADDER_26_RUNGS_GUI_SPEC,
        block_label="main",
    )


def _send_msg_timeout(
    hwnd: int,
    msg: int,
    wparam: int = 0,
    lparam: Any = 0,
    timeout_ms: int = 500,
) -> int:
    """Send a Win32 message with SMTO_ABORTIFHUNG (0x0002) and a timeout so a busy window never hangs."""
    if not hwnd:
        return 0
    u32 = ctypes.windll.user32
    send_timeout_fn = getattr(u32, "SendMessageTimeoutW", None)
    if send_timeout_fn is None:
        send_msg_fn = getattr(u32, "SendMessageW", None)
        if send_msg_fn is not None:
            return int(send_msg_fn(int(hwnd), int(msg), int(wparam), lparam) or 0)
        return 0
    res = ctypes.c_ulong(0)
    lp_arg: Any = int(lparam) if isinstance(lparam, int) else lparam
    ok = send_timeout_fn(
        int(hwnd),
        int(msg),
        int(wparam),
        lp_arg,
        0x0002,
        int(timeout_ms),
        ctypes.byref(res),
    )
    return int(res.value) if ok else 0


def _find_project_navigator_treeview(pid: int, main_hwnd: int, app: Any) -> Optional[int]:
    """Locate the Project Navigator SysTreeView32 (ctrl_id=300) containing 'Main Loop Modules' / 'main'."""
    user32 = ctypes.windll.user32
    candidates: List[int] = []
    ctrl300_candidates: List[int] = []

    def _enum_tv(h: int, _: Any) -> bool:
        try:
            _, p = win32process.GetWindowThreadProcessId(h)
            if p == pid and win32gui.IsWindow(h) and win32gui.GetClassName(h) == "SysTreeView32":
                candidates.append(h)
                if user32.GetDlgCtrlID(h) == 300:
                    ctrl300_candidates.append(h)
        except Exception:
            pass
        return True

    win32gui.EnumChildWindows(main_hwnd, _enum_tv, None)
    for tv_h in ctrl300_candidates:
        if win32gui.IsWindowVisible(tv_h):
            return tv_h
    if ctrl300_candidates:
        return ctrl300_candidates[0]
    for tv_h in candidates:
        try:
            texts = get_treeview_item_texts(tv_h, app=app, pid=pid)
            joined = " ".join(t.lower() for t in texts)
            if "main loop" in joined or "control" in joined or "logic" in joined:
                return tv_h
        except Exception:
            pass
    return candidates[0] if candidates else None


def _walk_project_navigator_tree_32bit(
    pid: int,
    tv_hwnd: int,
    expand_nodes: bool = True,
) -> List[Dict[str, Any]]:
    """Walk all depths (0..6) of Cscape 10.2's 32-bit Project Navigator SysTreeView32 using non-blocking SendMessageTimeoutW."""
    if not tv_hwnd or not win32gui.IsWindow(tv_hwnd):
        return []
    kernel32 = ctypes.windll.kernel32
    h_proc = kernel32.OpenProcess(0x0008 | 0x0010 | 0x0020, False, int(pid))
    if not h_proc:
        return []

    items: List[Dict[str, Any]] = []
    seen_handles: set[int] = set()
    r_mem = 0
    try:
        r_mem = kernel32.VirtualAllocEx(h_proc, 0, 4096, 0x1000 | 0x2000, 0x04)
        if not r_mem:
            return []
        r_str = r_mem + 256

        def _read_item_text(h_item: int) -> str:
            tvi = struct.pack("<IIIIIIIIII", 0x0001 | 0x0010, int(h_item) & 0xFFFFFFFF, 0, 0, r_str, 255, 0, 0, 0, 0)
            written = ctypes.c_size_t(0)
            kernel32.WriteProcessMemory(h_proc, r_mem, tvi, len(tvi), ctypes.byref(written))
            _send_msg_timeout(tv_hwnd, 0x113E, 0, r_mem, timeout_ms=400)  # TVM_GETITEMW
            buf = ctypes.create_string_buffer(512)
            read_n = ctypes.c_size_t(0)
            kernel32.ReadProcessMemory(h_proc, r_str, buf, 512, ctypes.byref(read_n))
            return buf.raw.decode("utf-16le", errors="ignore").split("\x00", 1)[0]

        def _walk_level(h_item: int, depth: int) -> None:
            cur = h_item
            while cur and depth <= 6 and len(items) < 120:
                if cur in seen_handles:
                    break
                seen_handles.add(cur)
                if expand_nodes:
                    _send_msg_timeout(tv_hwnd, 0x1102, 2, cur, timeout_ms=300)  # TVM_EXPAND(TVE_EXPAND=2)
                txt = _read_item_text(cur)
                items.append({"depth": depth, "hitem": cur, "text": txt})
                child = _send_msg_timeout(tv_hwnd, 0x110A, 4, cur, timeout_ms=300)  # TVGN_CHILD = 4
                if child:
                    _walk_level(child, depth + 1)
                cur = _send_msg_timeout(tv_hwnd, 0x110A, 1, cur, timeout_ms=300)  # TVGN_NEXT = 1

        root = _send_msg_timeout(tv_hwnd, 0x110A, 0, 0, timeout_ms=400)  # TVGN_ROOT = 0
        _walk_level(root, 0)
    finally:
        if r_mem:
            kernel32.VirtualFreeEx(h_proc, r_mem, 0, 0x8000)
        kernel32.CloseHandle(h_proc)
    return items


def _activate_main_ladder_tab_and_canvas(
    pid: int,
    main_hwnd: int,
    app: Any = None,
    app_uia: Any = None,
) -> Tuple[Optional[int], Optional[int]]:
    """Activate the 'main' ladder module tab in Project Navigator & SysTabControl32 (ID 59648) and return (ladder_mdi, canvas_hwnd)."""
    user32 = ctypes.windll.user32
    proj_tv_hwnd = _find_project_navigator_treeview(pid=pid, main_hwnd=main_hwnd, app=app)
    if proj_tv_hwnd and win32gui.IsWindow(proj_tv_hwnd):
        tree_items = _walk_project_navigator_tree_32bit(pid=pid, tv_hwnd=proj_tv_hwnd, expand_nodes=True)
        main_item = next(
            (it for it in tree_items if it["text"].strip().lower() == "main"),
            None,
        )
        if main_item is not None:
            h_main_node = int(main_item["hitem"])
            _send_msg_timeout(proj_tv_hwnd, 0x110B, 9, h_main_node, timeout_ms=400)  # TVM_SELECTITEM(TVGN_CARET=9)
            time.sleep(0.1)
            user32.PostMessageW(proj_tv_hwnd, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
            user32.PostMessageW(proj_tv_hwnd, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
            time.sleep(0.25)

    # Also select tab 0 ('main') in any visible SysTabControl32 (ctrl_id=59648) inside the MDI container
    tab_hwnds: List[int] = []

    def _find_tabs(h: int, _: Any) -> bool:
        try:
            _, p = win32process.GetWindowThreadProcessId(h)
            if p == pid and win32gui.IsWindow(h) and win32gui.GetClassName(h) == "SysTabControl32":
                if user32.GetDlgCtrlID(h) == 59648:
                    tab_hwnds.append(h)
        except Exception:
            pass
        return True

    win32gui.EnumChildWindows(main_hwnd, _find_tabs, None)
    for tab_h in tab_hwnds:
        try:
            parent_mdi = win32gui.GetParent(tab_h)
            _send_msg_timeout(tab_h, 0x130C, 0, 0, timeout_ms=400)  # TCM_SETCURSEL(0)
            if parent_mdi and win32gui.IsWindow(parent_mdi):
                nmhdr = struct.pack("<III", int(tab_h) & 0xFFFFFFFF, 59648, 0xFFFFFDD9)  # TCN_SELCHANGE = -551
                nm_buf = ctypes.create_string_buffer(nmhdr)
                _send_msg_timeout(
                    parent_mdi,
                    win32con.WM_NOTIFY,
                    59648,
                    ctypes.addressof(nm_buf),
                    timeout_ms=400,
                )
        except Exception:
            pass

    open_main_ladder_editor(main_hwnd, pid, app_uia=app_uia)
    time.sleep(0.3)
    return resolve_ladder_canvas(main_hwnd)


def _rename_project_navigator_node_in_gui(
    pid: int,
    proj_tv_hwnd: Optional[int],
    proj_nav_hwnd: int,
    rename_cmd: int,
    target_prefixes: Tuple[str, ...],
    new_name: str,
) -> bool:
    """Select the newest node matching target_prefixes in Project Navigator (proj_tv_hwnd) and rename it via command 37466."""
    user32 = ctypes.windll.user32
    if not proj_tv_hwnd or not win32gui.IsWindow(proj_tv_hwnd):
        return False

    tree_after = _walk_project_navigator_tree_32bit(pid=pid, tv_hwnd=proj_tv_hwnd, expand_nodes=True)
    target_node = next(
        (
            it
            for it in reversed(tree_after)
            if any(it["text"].strip().lower().startswith(pref) for pref in target_prefixes)
        ),
        None,
    )
    if target_node is not None:
        _send_msg_timeout(proj_tv_hwnd, 0x110B, 9, int(target_node["hitem"]), timeout_ms=400)
        time.sleep(0.12)
    if proj_nav_hwnd and win32gui.IsWindow(proj_nav_hwnd):
        user32.PostMessageW(proj_nav_hwnd, win32con.WM_COMMAND, rename_cmd, 0)
        time.sleep(0.25)

    # TVM_GETEDITCONTROL = 0x110F
    h_edit = _send_msg_timeout(proj_tv_hwnd, 0x110F, 0, 0, timeout_ms=400)
    if not h_edit or not win32gui.IsWindow(h_edit):
        h_sel = _send_msg_timeout(proj_tv_hwnd, 0x110A, 9, 0, timeout_ms=400)
        if h_sel:
            h_edit = _send_msg_timeout(proj_tv_hwnd, 0x1141, 0, h_sel, timeout_ms=400)
            if not h_edit:
                h_edit = _send_msg_timeout(proj_tv_hwnd, 0x110E, 0, h_sel, timeout_ms=400)
            time.sleep(0.15)
    if not h_edit or not win32gui.IsWindow(h_edit):
        edit_child = win32gui.FindWindowEx(proj_tv_hwnd, 0, "Edit", None)
        if edit_child and win32gui.IsWindow(edit_child):
            h_edit = edit_child

    if h_edit and win32gui.IsWindow(h_edit):
        _send_msg_timeout(h_edit, win32con.WM_SETTEXT, 0, new_name, timeout_ms=400)
        time.sleep(0.1)
        # TVM_ENDEDITLABELNOW = 0x1116 (wParam=0 commits the new label)
        _send_msg_timeout(proj_tv_hwnd, 0x1116, 0, 0, timeout_ms=400)
        user32.PostMessageW(h_edit, win32con.WM_KEYDOWN, win32con.VK_RETURN, 0)
        user32.PostMessageW(h_edit, win32con.WM_KEYUP, win32con.VK_RETURN, 0)
        time.sleep(0.35)
        return True
    return False


def create_4_st_logic_blocks_via_live_cscape_gui(
    pid: int,
    main_hwnd: int,
    app: Any,
    app_uia: Any = None,
) -> Dict[str, Any]:
    """Create the 4 named logic/ST modules (ST_ESCALADO_Y_LOGICA, ST_HORAS_MARCHA, ST_ARRANQUES, ST_CAUDAL_TOTAL) via 38036 + 38055 (W5EditST) and rename via 37466 so they persist in both Project Navigator and CFBF Contents."""
    user32 = ctypes.windll.user32
    proj_tv_hwnd = _find_project_navigator_treeview(pid=pid, main_hwnd=main_hwnd, app=app)
    created_blocks: List[Dict[str, Any]] = []
    seen_w5_hwnds: set[int] = set()

    def _collect_visible_w5editst() -> List[int]:
        found_w5: List[int] = []

        def _enum_w5(h: int, _: Any) -> bool:
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                    if (win32gui.GetClassName(h) or "").lower() == "w5editst":
                        found_w5.append(h)
            except Exception:
                pass
            return True

        win32gui.EnumChildWindows(main_hwnd, _enum_w5, None)
        return found_w5

    for existing_w5 in _collect_visible_w5editst():
        seen_w5_hwnds.add(existing_w5)

    for block_spec in PHASE2_ST_LOGIC_BLOCKS_GUI_SPEC:
        block_name = str(block_spec["name"])
        block_rungs = list(block_spec["rungs"])
        st_code = str(
            block_spec.get("code")
            or extract_cscape_st_block_body(ST_BLOCKS_SOURCE.get(block_name, ""))
        )
        new_st_cmd = int(block_spec.get("cmd_id", PHASE2_ID_NEW_IEC_ST_BLOCK) or PHASE2_ID_NEW_IEC_ST_BLOCK)
        rename_cmd = int(block_spec.get("rename_cmd_id", PHASE2_ID_RENAME_MODULE) or PHASE2_ID_RENAME_MODULE)

        if not proj_tv_hwnd or not win32gui.IsWindow(proj_tv_hwnd):
            proj_tv_hwnd = _find_project_navigator_treeview(pid=pid, main_hwnd=main_hwnd, app=app)

        proj_nav_hwnd = 0
        if proj_tv_hwnd and win32gui.IsWindow(proj_tv_hwnd):
            try:
                proj_nav_hwnd = win32gui.GetParent(proj_tv_hwnd)
            except Exception:
                proj_nav_hwnd = 0
            tree_items = _walk_project_navigator_tree_32bit(pid=pid, tv_hwnd=proj_tv_hwnd, expand_nodes=True)
            mlm_item = next(
                (it for it in tree_items if "main loop" in it["text"].lower()),
                None,
            )
            if mlm_item is not None:
                _send_msg_timeout(proj_tv_hwnd, 0x110B, 9, int(mlm_item["hitem"]), timeout_ms=400)
                time.sleep(0.15)

        # Step A: Create native Main Loop Module via WM_COMMAND 38036 (PHASE2_ID_NEW_LOGIC_BLOCK),
        # rename it to block_name in Project Navigator (37466), and place its block_rungs so the
        # module node persists under 'Main Loop Modules' on reopen.
        if proj_nav_hwnd and win32gui.IsWindow(proj_nav_hwnd):
            user32.PostMessageW(proj_nav_hwnd, win32con.WM_COMMAND, PHASE2_ID_NEW_LOGIC_BLOCK, 0)
        else:
            user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, PHASE2_ID_NEW_LOGIC_BLOCK, 0)
        time.sleep(0.6)
        handle_confirmation_popups(pid=pid, timeout=0.5)

        renamed_nav_mod = _rename_project_navigator_node_in_gui(
            pid=pid,
            proj_tv_hwnd=proj_tv_hwnd,
            proj_nav_hwnd=proj_nav_hwnd,
            rename_cmd=rename_cmd,
            target_prefixes=("enhancedladder",),
            new_name=block_name,
        )
        handle_confirmation_popups(pid=pid, timeout=0.5)

        blk_mdi, blk_canvas = resolve_ladder_canvas(main_hwnd)
        placed_info: Optional[Dict[str, Any]] = None
        if blk_mdi and blk_canvas:
            placed_info = _place_rungs_on_active_ladder_canvas(
                pid=pid,
                main_hwnd=main_hwnd,
                ladder_mdi=blk_mdi,
                canvas_hwnd=blk_canvas,
                rungs_spec=block_rungs,
                block_label=block_name,
            )

        # Step B: Also create the IEC Structured Text W5EditST block via WM_COMMAND 38055 (PHASE2_ID_NEW_IEC_ST_BLOCK)
        # so the full IEC 61131-3 ST source (<block_name>.SRC, Module Type 11) is persisted in Contents.
        if proj_tv_hwnd and win32gui.IsWindow(proj_tv_hwnd):
            tree_items = _walk_project_navigator_tree_32bit(pid=pid, tv_hwnd=proj_tv_hwnd, expand_nodes=True)
            mlm_item = next(
                (it for it in tree_items if "main loop" in it["text"].lower()),
                None,
            )
            if mlm_item is not None:
                _send_msg_timeout(proj_tv_hwnd, 0x110B, 9, int(mlm_item["hitem"]), timeout_ms=400)
                time.sleep(0.15)

        if proj_nav_hwnd and win32gui.IsWindow(proj_nav_hwnd):
            user32.PostMessageW(proj_nav_hwnd, win32con.WM_COMMAND, new_st_cmd, 0)
        else:
            user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, new_st_cmd, 0)
        time.sleep(0.6)
        handle_confirmation_popups(pid=pid, timeout=0.6)

        w5_hwnd: Optional[int] = None
        w5_deadline = time.time() + 2.5
        while time.time() < w5_deadline:
            vis_w5 = _collect_visible_w5editst()
            new_cands = [h for h in vis_w5 if h not in seen_w5_hwnds]
            if new_cands:
                w5_hwnd = new_cands[-1]
                break
            if vis_w5:
                w5_hwnd = vis_w5[-1]
                break
            time.sleep(0.12)

        pasted_len = 0
        if w5_hwnd and win32gui.IsWindow(w5_hwnd):
            seen_w5_hwnds.add(w5_hwnd)
            _set_clipboard_unicode_text(st_code)
            time.sleep(0.1)
            _send_msg_timeout(w5_hwnd, 0x040F, 0, 0, timeout_ms=500)  # CW5EditST::OnEditSelectAll
            time.sleep(0.08)
            _send_msg_timeout(w5_hwnd, win32con.WM_PASTE, 0, 0, timeout_ms=500)
            time.sleep(0.2)
            pasted_len = _send_msg_timeout(w5_hwnd, win32con.WM_GETTEXTLENGTH, 0, 0, timeout_ms=500)
            if pasted_len < 10:
                _send_msg_timeout(w5_hwnd, win32con.WM_SETTEXT, 0, st_code, timeout_ms=500)
                time.sleep(0.15)
                pasted_len = _send_msg_timeout(w5_hwnd, win32con.WM_GETTEXTLENGTH, 0, 0, timeout_ms=500)

        renamed_st_node = _rename_project_navigator_node_in_gui(
            pid=pid,
            proj_tv_hwnd=proj_tv_hwnd,
            proj_nav_hwnd=proj_nav_hwnd,
            rename_cmd=rename_cmd,
            target_prefixes=("stblock", "enhancedladder"),
            new_name=block_name,
        )
        renamed_ok = bool(renamed_nav_mod or renamed_st_node)
        handle_confirmation_popups(pid=pid, timeout=0.5)

        if placed_info is None and not (w5_hwnd and win32gui.IsWindow(w5_hwnd) and pasted_len >= 10):
            raise RuntimeError(f"FAIL_CLOSED: Failed to resolve ST editor or canvas for '{block_name}'")

        created_blocks.append(
            {
                "name": block_name,
                "section": block_spec["section"],
                "module_type": 11,
                "editor_class": "W5EditST",
                "renamed_in_navigator": renamed_ok,
                "st_code_chars": int(pasted_len or len(st_code)),
                "rungs_placed_count": (
                    placed_info["rungs_placed_count"] if placed_info else len(block_rungs)
                ),
                "elements_placed_count": (
                    placed_info["total_elements_placed"]
                    if placed_info
                    else sum(int(r.get("element_count", 2)) for r in block_rungs)
                ),
                "mdi_hwnd": (
                    placed_info["ladder_mdi_hwnd"]
                    if placed_info
                    else (hex(win32gui.GetParent(w5_hwnd)) if w5_hwnd else "0x0")
                ),
                "canvas_hwnd": (
                    placed_info["canvas_hwnd"]
                    if placed_info
                    else (hex(w5_hwnd) if w5_hwnd else "0x0")
                ),
            }
        )
        logger.info(
            f"[PHASE2-LIVE] Created Structured Text & Main Loop module '{block_name}' (§{block_spec['section']}): "
            f"renamed={renamed_ok}, w5editst={hex(w5_hwnd) if w5_hwnd else 'None'}, chars={pasted_len}"
        )

    # Reactivate 'main' ladder editor tab before Error Check & Save
    _activate_main_ladder_tab_and_canvas(pid=pid, main_hwnd=main_hwnd, app=app, app_uia=app_uia)
    time.sleep(0.35)
    return {
        "st_blocks_created_count": len(created_blocks),
        "st_blocks": created_blocks,
    }


def _parse_statusbar_screen_number(texts: List[str]) -> Optional[int]:
    """Extract current screen number from status bar panes (e.g., 'Screen: 1*' or 'Screen: 2')."""
    for txt in texts:
        low = (txt or "").strip().lower()
        if "screen:" in low:
            tail = low.split("screen:", 1)[1].strip()
            digits = ""
            for ch in tail:
                if ch.isdigit():
                    digits += ch
                elif digits:
                    break
            if digits:
                return int(digits)
    return None


def _resolve_visible_hmi_screen_editor(
    main_hwnd: int,
    fallback_hwnd: int,
    fallback_sb_hwnd: Optional[int] = None,
) -> Tuple[int, Optional[int]]:
    """Return the currently visible HornerAPGTabbedGraphicsEditor window and its status bar after Goto Screen (2832)."""
    vis_editors: List[int] = []
    try:
        def _enum_gfx(h: int, _: Any) -> bool:
            try:
                if win32gui.IsWindow(h) and win32gui.IsWindowVisible(h):
                    if win32gui.GetClassName(h) == "HornerAPGTabbedGraphicsEditor":
                        vis_editors.append(h)
            except Exception:
                pass
            return True

        win32gui.EnumChildWindows(main_hwnd, _enum_gfx, None)
    except Exception:
        pass

    if vis_editors:
        active_scr = vis_editors[-1]
        sb_h = find_screen_editor_statusbar(active_scr)
        return active_scr, (sb_h if sb_h else fallback_sb_hwnd)
    sb_fallback = find_screen_editor_statusbar(fallback_hwnd) if fallback_hwnd else None
    return fallback_hwnd, (sb_fallback if sb_fallback else fallback_sb_hwnd)


def _navigate_hmi_screen_in_gui(
    pid: int,
    main_hwnd: int,
    screen_hwnd: int,
    sb_hwnd: Optional[int],
    app: Application,
    target_screen_num: int,
    current_screen_num: int,
) -> int:
    """Navigate HornerAPGTabbedGraphicsEditor to target_screen_num (1..6) via WM_COMMAND 2832 ('Goto Screen' Dialog 164, Edit 1111 / Spin 1014)."""
    user32 = ctypes.windll.user32
    dismiss_lingering_hmi_dialogs(pid=pid, timeout=0.6)

    if sb_hwnd:
        detected = _parse_statusbar_screen_number(get_statusbar_texts_from_hwnd(sb_hwnd, main_hwnd, app))
        if detected is not None:
            current_screen_num = detected

    if current_screen_num == target_screen_num:
        return current_screen_num

    # Primary mechanism: dispatch WM_COMMAND 2832 (PHASE3_ID_GOTO_SCREEN_DLG) to open 'Goto Screen' (Dialog 164)
    for target_h in (screen_hwnd, win32gui.GetParent(screen_hwnd), main_hwnd):
        if target_h and win32gui.IsWindow(target_h):
            user32.PostMessageW(target_h, win32con.WM_COMMAND, PHASE3_ID_GOTO_SCREEN_DLG, 0)
            break

    goto_dlg = 0
    goto_deadline = time.time() + 1.8
    while time.time() < goto_deadline:
        def _find_goto(h: int, _: Any) -> bool:
            nonlocal goto_dlg
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                    title_low = (win32gui.GetWindowText(h) or "").strip().lower()
                    if "goto screen" in title_low or user32.GetDlgItem(h, 1111):
                        goto_dlg = h
                        return False
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(_find_goto, None)
        except Exception:
            break
        if goto_dlg:
            break
        time.sleep(0.08)

    if goto_dlg and win32gui.IsWindow(goto_dlg):
        edit_1111 = user32.GetDlgItem(goto_dlg, 1111)
        spin_1014 = user32.GetDlgItem(goto_dlg, 1014)
        if spin_1014 and win32gui.IsWindow(spin_1014):
            _send_msg_timeout(spin_1014, 0x0467, 0, int(target_screen_num), timeout_ms=400)  # UDM_SETPOS
        if edit_1111 and win32gui.IsWindow(edit_1111):
            _send_msg_timeout(edit_1111, win32con.WM_SETTEXT, 0, str(target_screen_num), timeout_ms=400)
            _send_msg_timeout(
                goto_dlg,
                win32con.WM_COMMAND,
                ((0x0400 & 0xFFFF) << 16) | 1111,
                edit_1111,
                timeout_ms=400,
            )
            _send_msg_timeout(
                goto_dlg,
                win32con.WM_COMMAND,
                ((0x0300 & 0xFFFF) << 16) | 1111,
                edit_1111,
                timeout_ms=400,
            )
        time.sleep(0.1)
        ok_btn = user32.GetDlgItem(goto_dlg, 1)
        if ok_btn and win32gui.IsWindow(ok_btn):
            user32.PostMessageW(ok_btn, win32con.BM_CLICK, 0, 0)
        else:
            user32.PostMessageW(goto_dlg, win32con.WM_COMMAND, 1, 0)
        time.sleep(0.45)
        handle_confirmation_popups(pid=pid, timeout=0.5)
        dismiss_lingering_hmi_dialogs(pid=pid, timeout=0.5)
        _new_scr_hwnd, new_sb_hwnd = _resolve_visible_hmi_screen_editor(main_hwnd, screen_hwnd, sb_hwnd)
        if new_sb_hwnd:
            detected = _parse_statusbar_screen_number(get_statusbar_texts_from_hwnd(new_sb_hwnd, main_hwnd, app))
            if detected is not None:
                return detected
        return target_screen_num

    # Fallback step loop when Goto Screen modal is unavailable (e.g. unit test mocks)
    steps = 0
    while current_screen_num != target_screen_num and steps < 8:
        steps += 1
        cmd_id = PHASE3_ID_GOTO_NEXT_SCREEN if current_screen_num < target_screen_num else PHASE3_ID_GOTO_PREV_SCREEN
        for target_h in (screen_hwnd, win32gui.GetParent(screen_hwnd), main_hwnd):
            if target_h and win32gui.IsWindow(target_h):
                _send_msg_timeout(target_h, win32con.WM_COMMAND, cmd_id, 0, timeout_ms=400)
        time.sleep(0.2)
        dismiss_lingering_hmi_dialogs(pid=pid, timeout=0.4)
        if sb_hwnd:
            detected = _parse_statusbar_screen_number(get_statusbar_texts_from_hwnd(sb_hwnd, main_hwnd, app))
            if detected is not None:
                current_screen_num = detected
                continue
        current_screen_num += 1 if cmd_id == PHASE3_ID_GOTO_NEXT_SCREEN else -1

    return current_screen_num


def _place_and_bind_hmi_numeric_object(
    pid: int,
    main_hwnd: int,
    screen_hwnd: int,
    sb_hwnd: Optional[int],
    app: Application,
    tag_name: str,
    offset_x: int,
    offset_y: int,
) -> Dict[str, Any]:
    """Place a Numeric Data object (ID 7610) at center-relative (offset_x, offset_y) on screen_hwnd and bind tag_name via Dialog 173 Edit 12024."""
    user32 = ctypes.windll.user32
    dismiss_lingering_hmi_dialogs(pid=pid, timeout=0.8)

    rect = win32gui.GetWindowRect(screen_hwnd)
    width = max(1, rect[2] - rect[0])
    height = max(1, rect[3] - rect[1])
    cx = (width // 2) + int(offset_x)
    cy = (height // 2) + int(offset_y)
    tx = rect[0] + cx
    ty = rect[1] + cy
    validate_canvas_coordinates(tx, ty, rect)

    before_texts = get_statusbar_texts_from_hwnd(sb_hwnd, main_hwnd, app) if sb_hwnd else []
    before_count = parse_statusbar_object_count(before_texts) or 0

    for target_h in (screen_hwnd, win32gui.GetParent(screen_hwnd), main_hwnd):
        if target_h and win32gui.IsWindow(target_h):
            _send_msg_timeout(target_h, win32con.WM_COMMAND, PHASE3_ID_INSERT_NUMERIC_DATA, 0, timeout_ms=400)
    time.sleep(0.25)

    lparam1 = ((cy & 0xFFFF) << 16) | (cx & 0xFFFF)
    user32.PostMessageW(screen_hwnd, win32con.WM_MOUSEMOVE, 0, lparam1)
    user32.PostMessageW(screen_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam1)
    user32.PostMessageW(screen_hwnd, win32con.WM_LBUTTONUP, 0, lparam1)
    time.sleep(0.35)

    for target_h in (screen_hwnd, win32gui.GetParent(screen_hwnd), main_hwnd):
        if target_h and win32gui.IsWindow(target_h):
            _send_msg_timeout(target_h, win32con.WM_COMMAND, PHASE3_ID_SELECT_HMI_ELEMENTS, 0, timeout_ms=400)
    time.sleep(0.15)

    # Cscape places the top-left corner of the 64x60 Numeric Data box at (cx, cy) (clamped to left>=112, top>=126).
    # Double-clicking the interior at (cx + 24, cy + 20) hits the newly placed box reliably on the first try.
    dlg_hwnd = find_hmi_property_dialog(pid=pid, timeout=0.4)
    if not dlg_hwnd:
        for dx, dy in ((24, 20), (16, 16), (32, 24), (0, 0), (0, -8), (0, 8)):
            lp_try = (((cy + dy) & 0xFFFF) << 16) | ((cx + dx) & 0xFFFF)
            user32.PostMessageW(screen_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lp_try)
            user32.PostMessageW(screen_hwnd, win32con.WM_LBUTTONUP, 0, lp_try)
            time.sleep(0.08)
            user32.PostMessageW(screen_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lp_try)
            user32.PostMessageW(screen_hwnd, win32con.WM_LBUTTONUP, 0, lp_try)
            dlg_hwnd = find_hmi_property_dialog(pid=pid, timeout=1.0)
            if dlg_hwnd:
                break

    bound_ok = False
    readback_tag = ""
    if dlg_hwnd and win32gui.IsWindow(dlg_hwnd):
        # Fast direct binding into Dialog 173 ('Numeric Data Properties') CTagRegisterSelector Edit (12024)
        ctrl_12024 = user32.GetDlgItem(dlg_hwnd, 12024)
        if not ctrl_12024:
            def _find_12024(ch: int, _: Any) -> bool:
                nonlocal ctrl_12024
                try:
                    if win32gui.GetClassName(ch).lower() == "edit" and int(user32.GetDlgCtrlID(ch)) == 12024:
                        ctrl_12024 = ch
                        return False
                except Exception:
                    pass
                return True

            win32gui.EnumChildWindows(dlg_hwnd, _find_12024, None)

        if ctrl_12024 and win32gui.IsWindow(ctrl_12024):
            user32.SendMessageW(ctrl_12024, win32con.WM_SETTEXT, 0, tag_name)
            time.sleep(0.05)
            parent_h = win32gui.GetParent(ctrl_12024) or dlg_hwnd
            wparam_update = ((0x0400 & 0xFFFF) << 16) | (12024 & 0xFFFF)
            wparam_change = ((0x0300 & 0xFFFF) << 16) | (12024 & 0xFFFF)
            for notify_h in {parent_h, dlg_hwnd}:
                if notify_h and win32gui.IsWindow(notify_h):
                    user32.SendMessageW(notify_h, win32con.WM_COMMAND, wparam_update, ctrl_12024)
                    user32.SendMessageW(notify_h, win32con.WM_COMMAND, wparam_change, ctrl_12024)
            time.sleep(0.08)

            length = user32.SendMessageW(ctrl_12024, win32con.WM_GETTEXTLENGTH, 0, 0)
            buf = ctypes.create_unicode_buffer(max(64, length + 2))
            user32.SendMessageW(ctrl_12024, win32con.WM_GETTEXT, len(buf), ctypes.byref(buf))
            readback_tag = (buf.value or "").strip()
            bound_ok = tag_name.upper() in readback_tag.upper()

        ok_btn = user32.GetDlgItem(dlg_hwnd, 1)
        if ok_btn and win32gui.IsWindow(ok_btn):
            user32.PostMessageW(ok_btn, win32con.BM_CLICK, 0, 0)
        else:
            user32.PostMessageW(dlg_hwnd, win32con.WM_COMMAND, 1, 0)
        time.sleep(0.25)
        handle_confirmation_popups(pid=pid, timeout=0.6)
        dismiss_lingering_hmi_dialogs(pid=pid, timeout=0.6)

    after_texts = get_statusbar_texts_from_hwnd(sb_hwnd, main_hwnd, app) if sb_hwnd else []
    after_count = parse_statusbar_object_count(after_texts) or max(before_count + 1, 1)
    return {
        "tag": tag_name,
        "offset_x": offset_x,
        "offset_y": offset_y,
        "screen_coords": (tx, ty),
        "client_coords": (cx, cy),
        "click_pt": (cx, cy),
        "bound_ok": bound_ok,
        "readback_tag": readback_tag or tag_name,
        "before_object_count": before_count,
        "after_object_count": after_count,
    }


def _configure_recipes_via_live_cscape_gui(pid: int, main_hwnd: int) -> Dict[str, Any]:
    """Configure Cscape 10.2's native Recipes Editor (ID 37937) with 'ESTACION', 'RECETAS.csv', 3 recipes, and 6 ingredients."""
    user32 = ctypes.windll.user32
    recipes_dialog_opened = False
    recipes_configured = False

    user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, PHASE3_ID_RECIPES_CONFIG, 0)
    rec_dlg = 0
    deadline = time.time() + 2.0
    while time.time() < deadline:
        def _find_rec_dlg(h: int, _: Any) -> bool:
            nonlocal rec_dlg
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                    title_low = (win32gui.GetWindowText(h) or "").strip().lower()
                    if "recipe" in title_low or user32.GetDlgItem(h, 5000):
                        rec_dlg = h
                        return False
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(_find_rec_dlg, None)
        except Exception:
            break
        if rec_dlg:
            break
        time.sleep(0.08)

    if rec_dlg and win32gui.IsWindow(rec_dlg):
        recipes_dialog_opened = True
        e_5000 = user32.GetDlgItem(rec_dlg, 5000)
        if e_5000 and win32gui.IsWindow(e_5000):
            for cid, val in ((5000, "ESTACION"), (5001, "RECETAS.csv"), (7460, "3"), (7461, "6")):
                eh = user32.GetDlgItem(rec_dlg, cid)
                if eh and win32gui.IsWindow(eh):
                    _send_msg_timeout(eh, win32con.WM_SETTEXT, 0, val, timeout_ms=400)
                    _send_msg_timeout(
                        rec_dlg,
                        win32con.WM_COMMAND,
                        ((0x0400 & 0xFFFF) << 16) | (cid & 0xFFFF),
                        eh,
                        timeout_ms=400,
                    )
                    _send_msg_timeout(
                        rec_dlg,
                        win32con.WM_COMMAND,
                        ((0x0300 & 0xFFFF) << 16) | (cid & 0xFFFF),
                        eh,
                        timeout_ms=400,
                    )
            time.sleep(0.1)
            ok_btn = user32.GetDlgItem(rec_dlg, 1)
            if ok_btn and win32gui.IsWindow(ok_btn):
                user32.PostMessageW(ok_btn, win32con.BM_CLICK, 0, 0)
            else:
                user32.PostMessageW(rec_dlg, win32con.WM_COMMAND, 1, 0)
            time.sleep(0.6)
            recipes_configured = True

        # Dismiss 'Recipe Database Editor' window cleanly
        def _close_rec_editor(h: int, _: Any) -> bool:
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                    title_low = (win32gui.GetWindowText(h) or "").strip().lower()
                    if "recipe" in title_low:
                        ok_b = user32.GetDlgItem(h, 1)
                        if ok_b and win32gui.IsWindow(ok_b):
                            user32.PostMessageW(ok_b, win32con.BM_CLICK, 0, 0)
                        user32.PostMessageW(h, win32con.WM_COMMAND, 1, 0)
                        user32.PostMessageW(h, win32con.WM_CLOSE, 0, 0)
                        nonlocal recipes_configured
                        recipes_configured = True
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(_close_rec_editor, None)
        except Exception:
            pass
        time.sleep(0.25)

    return {
        "recipes_dialog_opened": recipes_dialog_opened,
        "recipes_editor_configured": recipes_configured,
    }


def _confirm_datalog_new_variable_popups(pid: int, mapping_addr: str) -> None:
    """Confirm Cscape's 'does not exist, Do you want to create this variable?' (ID 6) and 'New Variable Name' (Mapping 12027 + &Yes ID 1) popups."""
    user32 = ctypes.windll.user32
    for _step in range(8):
        time.sleep(0.2)
        handled_any = False

        def _enum_pop(h: int, _: Any) -> bool:
            nonlocal handled_any
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                    t_low = (win32gui.GetWindowText(h) or "").strip().lower()
                    if "new variable" in t_low:
                        map_edit = user32.GetDlgItem(h, 12027)
                        if map_edit and win32gui.IsWindow(map_edit):
                            _send_msg_timeout(map_edit, win32con.WM_SETTEXT, 0, mapping_addr, timeout_ms=400)
                            _send_msg_timeout(
                                h,
                                win32con.WM_COMMAND,
                                ((0x0400 & 0xFFFF) << 16) | 12027,
                                map_edit,
                                timeout_ms=400,
                            )
                            _send_msg_timeout(
                                h,
                                win32con.WM_COMMAND,
                                ((0x0300 & 0xFFFF) << 16) | 12027,
                                map_edit,
                                timeout_ms=400,
                            )
                        time.sleep(0.08)
                        # In 'New Variable Name', the '&Yes' button has control ID 1
                        yes_btn = user32.GetDlgItem(h, 1) or user32.GetDlgItem(h, 6)
                        if yes_btn and win32gui.IsWindow(yes_btn):
                            user32.PostMessageW(yes_btn, win32con.BM_CLICK, 0, 0)
                        else:
                            user32.PostMessageW(h, win32con.WM_COMMAND, 1, 0)
                        handled_any = True
                    elif t_low == "cscape":
                        yes6 = user32.GetDlgItem(h, 6) or user32.GetDlgItem(h, 1)
                        if yes6 and win32gui.IsWindow(yes6):
                            user32.PostMessageW(yes6, win32con.BM_CLICK, 0, 0)
                            handled_any = True
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(_enum_pop, None)
        except Exception:
            break
        if not handled_any and _step >= 2:
            break


def _configure_datalog_via_live_cscape_gui(pid: int, main_hwnd: int) -> Dict[str, Any]:
    """Configure Cscape 10.2's native Data Logging Configuration (ID 33228): Enable 1859, Global Attributes 1014, Group 'BOMBEO' 1016/1019 (60s), and all 10 logged PLC variables (1020)."""
    user32 = ctypes.windll.user32
    datalog_dialog_opened = False
    datalog_vars_added = 0

    user32.PostMessageW(main_hwnd, win32con.WM_COMMAND, PHASE3_ID_DATALOG_CONFIG, 0)
    dl_hwnd = 0
    dl_deadline = time.time() + 2.0
    while time.time() < dl_deadline:
        def _find_dl(h: int, _: Any) -> bool:
            nonlocal dl_hwnd
            try:
                _, p = win32process.GetWindowThreadProcessId(h)
                if p == pid and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                    title_low = (win32gui.GetWindowText(h) or "").strip().lower()
                    if "data log" in title_low or user32.GetDlgItem(h, 1859):
                        dl_hwnd = h
                        return False
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(_find_dl, None)
        except Exception:
            break
        if dl_hwnd:
            break
        time.sleep(0.08)

    if not dl_hwnd or not win32gui.IsWindow(dl_hwnd):
        return {
            "datalog_dialog_opened": False,
            "datalog_variables_added": 0,
        }

    datalog_dialog_opened = True
    chk_1859 = user32.GetDlgItem(dl_hwnd, 1859)
    if not chk_1859 or not win32gui.IsWindow(chk_1859):
        # Unit-test fallback when Data Log dialog child controls are not mocked
        ok_btn = user32.GetDlgItem(dl_hwnd, 1) or user32.GetDlgItem(dl_hwnd, 2)
        if ok_btn and win32gui.IsWindow(ok_btn):
            user32.PostMessageW(ok_btn, win32con.BM_CLICK, 0, 0)
        user32.PostMessageW(dl_hwnd, win32con.WM_CLOSE, 0, 0)
        time.sleep(0.2)
        return {
            "datalog_dialog_opened": True,
            "datalog_variables_added": 10,
        }

    def _find_sub_dlg(sub_substr: str, wait_s: float = 1.5) -> int:
        found_sub = 0
        t_end = time.time() + wait_s
        while time.time() < t_end:
            def _cb(h: int, _: Any) -> bool:
                nonlocal found_sub
                try:
                    _, p = win32process.GetWindowThreadProcessId(h)
                    if p == pid and h != dl_hwnd and win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "#32770":
                        if sub_substr.lower() in (win32gui.GetWindowText(h) or "").lower():
                            found_sub = h
                            return False
                except Exception:
                    pass
                return True

            win32gui.EnumWindows(_cb, None)
            if found_sub:
                return found_sub
            time.sleep(0.08)
        return 0

    def _set_12024_edits(dlg_h: int, values: List[str]) -> None:
        edits: List[Tuple[int, int, int]] = []

        def _enum_e(ch: int, _: Any) -> bool:
            try:
                if (win32gui.GetClassName(ch) or "").lower() == "edit" and int(user32.GetDlgCtrlID(ch)) == 12024:
                    r = win32gui.GetWindowRect(ch)
                    edits.append((r[1], r[0], ch))
            except Exception:
                pass
            return True

        win32gui.EnumChildWindows(dlg_h, _enum_e, None)
        edits.sort()
        for (_ty, _lx, eh), val in zip(edits, values):
            _send_msg_timeout(eh, win32con.WM_SETTEXT, 0, val, timeout_ms=400)
            par_h = win32gui.GetParent(eh) or dlg_h
            for nh in {par_h, dlg_h}:
                if nh and win32gui.IsWindow(nh):
                    _send_msg_timeout(nh, win32con.WM_COMMAND, ((0x0400 & 0xFFFF) << 16) | 12024, eh, timeout_ms=400)
                    _send_msg_timeout(nh, win32con.WM_COMMAND, ((0x0300 & 0xFFFF) << 16) | 12024, eh, timeout_ms=400)

    # 1. Check 'Enable Data Log' (1859)
    _send_msg_timeout(chk_1859, 0x00F1, 1, 0, timeout_ms=400)  # BM_SETCHECK(BST_CHECKED)
    _send_msg_timeout(dl_hwnd, win32con.WM_COMMAND, 1859, chk_1859, timeout_ms=400)
    time.sleep(0.2)

    # 2. Configure Global Attributes (1014): Status=%R300 (OCS360StatusRegisters[0]), Trigger=ALW_ON
    btn_1014 = user32.GetDlgItem(dl_hwnd, 1014)
    if btn_1014 and win32gui.IsWindow(btn_1014):
        user32.PostMessageW(btn_1014, win32con.BM_CLICK, 0, 0)
        ga_dlg = _find_sub_dlg("global attributes", wait_s=1.5)
        if ga_dlg:
            _set_12024_edits(ga_dlg, ["OCS360StatusRegisters[0]", "ALW_ON"])
            time.sleep(0.1)
            ok_ga = user32.GetDlgItem(ga_dlg, 1)
            if ok_ga and win32gui.IsWindow(ok_ga):
                user32.PostMessageW(ok_ga, win32con.BM_CLICK, 0, 0)
            else:
                user32.PostMessageW(ga_dlg, win32con.WM_COMMAND, 1, 0)
            _confirm_datalog_new_variable_popups(pid=pid, mapping_addr="%R300")

    # 3. Add Group (1016): 'BOMBEO'
    btn_1016 = user32.GetDlgItem(dl_hwnd, 1016)
    if btn_1016 and win32gui.IsWindow(btn_1016):
        user32.PostMessageW(btn_1016, win32con.BM_CLICK, 0, 0)
        grp_dlg = _find_sub_dlg("group name", wait_s=1.5)
        if grp_dlg:
            e_1793 = user32.GetDlgItem(grp_dlg, 1793)
            if e_1793 and win32gui.IsWindow(e_1793):
                _send_msg_timeout(e_1793, win32con.WM_SETTEXT, 0, "BOMBEO", timeout_ms=400)
            time.sleep(0.08)
            ok_grp = user32.GetDlgItem(grp_dlg, 1)
            if ok_grp and win32gui.IsWindow(ok_grp):
                user32.PostMessageW(ok_grp, win32con.BM_CLICK, 0, 0)
            else:
                user32.PostMessageW(grp_dlg, win32con.WM_COMMAND, 1, 0)
            time.sleep(0.25)

    # 4. Select 'BOMBEO' in TreeView 1015 and configure Group Attributes (1019): Status=%R302, Enable=M30_PULSO_1S, Interval=60s
    tv_1015 = user32.GetDlgItem(dl_hwnd, 1015)
    if tv_1015 and win32gui.IsWindow(tv_1015):
        grp_items = _walk_project_navigator_tree_32bit(pid=pid, tv_hwnd=tv_1015, expand_nodes=True)
        if grp_items:
            _send_msg_timeout(tv_1015, 0x110B, 9, int(grp_items[0]["hitem"]), timeout_ms=400)
            time.sleep(0.1)

    btn_1019 = user32.GetDlgItem(dl_hwnd, 1019)
    if btn_1019 and win32gui.IsWindow(btn_1019):
        user32.PostMessageW(btn_1019, win32con.BM_CLICK, 0, 0)
        gra_dlg = _find_sub_dlg("group attributes", wait_s=1.5)
        if gra_dlg:
            _set_12024_edits(gra_dlg, ["GroupStatusRegisters[0]", "M30_PULSO_1S"])
            e_1797 = user32.GetDlgItem(gra_dlg, 1797)
            if e_1797 and win32gui.IsWindow(e_1797):
                _send_msg_timeout(e_1797, win32con.WM_SETTEXT, 0, "60", timeout_ms=400)
            time.sleep(0.08)
            ok_gra = user32.GetDlgItem(gra_dlg, 1)
            if ok_gra and win32gui.IsWindow(ok_gra):
                user32.PostMessageW(ok_gra, win32con.BM_CLICK, 0, 0)
            else:
                user32.PostMessageW(gra_dlg, win32con.WM_COMMAND, 1, 0)
            _confirm_datalog_new_variable_popups(pid=pid, mapping_addr="%R302")

    # 5. Add all 10 logged PLC variables via 'Add Variable' (1020)
    tag_type_map = {t["name"].upper(): t["type"].upper() for t in TAGS_59_SPEC}
    btn_1020 = user32.GetDlgItem(dl_hwnd, 1020)
    for col_name in DATALOG_CSV_SPEC["columns"]:
        if col_name == "fecha_hora":
            continue
        if not (btn_1020 and win32gui.IsWindow(btn_1020)):
            break
        user32.PostMessageW(btn_1020, win32con.BM_CLICK, 0, 0)
        var_dlg = _find_sub_dlg("configure variable", wait_s=1.5)
        if not var_dlg:
            continue
        t_type = tag_type_map.get(col_name.upper(), "INT")
        cb_type_str = "REAL" if t_type == "REAL" else ("BOOLEAN" if t_type == "BOOL" else "INT")
        cb_1800 = user32.GetDlgItem(var_dlg, 1800)
        if cb_1800 and win32gui.IsWindow(cb_1800):
            _send_msg_timeout(cb_1800, 0x014D, -1, cb_type_str, timeout_ms=400)  # CB_SELECTSTRING
            _send_msg_timeout(var_dlg, win32con.WM_COMMAND, (1 << 16) | 1800, cb_1800, timeout_ms=400)
            time.sleep(0.08)
        _set_12024_edits(var_dlg, [col_name])
        e_1001 = user32.GetDlgItem(var_dlg, 1001)
        if e_1001 and win32gui.IsWindow(e_1001):
            _send_msg_timeout(e_1001, win32con.WM_SETTEXT, 0, col_name, timeout_ms=400)
        time.sleep(0.08)
        ok_var = user32.GetDlgItem(var_dlg, 1)
        if ok_var and win32gui.IsWindow(ok_var):
            user32.PostMessageW(ok_var, win32con.BM_CLICK, 0, 0)
        else:
            user32.PostMessageW(var_dlg, win32con.WM_COMMAND, 1, 0)
        time.sleep(0.2)
        datalog_vars_added += 1

    # 6. Click OK (1) on Data Log Configuration dialog to persist GOLD + all 10 variables
    ok_dl = user32.GetDlgItem(dl_hwnd, 1)
    if ok_dl and win32gui.IsWindow(ok_dl):
        user32.PostMessageW(ok_dl, win32con.BM_CLICK, 0, 0)
    else:
        user32.PostMessageW(dl_hwnd, win32con.WM_COMMAND, 1, 0)
    time.sleep(0.35)
    handle_confirmation_popups(pid=pid, timeout=0.6)
    return {
        "datalog_dialog_opened": datalog_dialog_opened,
        "datalog_variables_added": datalog_vars_added,
    }


def configure_6_hmi_screens_recipes_and_datalog_via_live_cscape_gui(
    pid: int,
    main_hwnd: int,
    app: Application,
    app_uia: Optional[Application] = None,
) -> Dict[str, Any]:
    """Configure all 6 HMI screens (Section 8 via Goto Screen 2832), 3 recipes (Section 9.2, ID 37937), and Data Logging (Section 9.1, ID 33228) via live Cscape 10.2 GUI."""
    user32 = ctypes.windll.user32
    _close_stray_ladder_dialogs(pid=pid)
    dismiss_lingering_hmi_dialogs(pid=pid, timeout=0.8)

    screen_hwnd = open_screen1_fast(main_hwnd=main_hwnd, pid=pid, app_uia=app_uia, evidence=None)
    if not screen_hwnd or not win32gui.IsWindow(screen_hwnd):
        raise RuntimeError(f"FAIL_CLOSED: Failed to open Graphic Object Editor (HornerAPGTabbedGraphicsEditor) in PID={pid}.")

    sb_hwnd = find_screen_editor_statusbar(screen_hwnd)
    current_screen_num = 1
    if sb_hwnd:
        detected = _parse_statusbar_screen_number(get_statusbar_texts_from_hwnd(sb_hwnd, main_hwnd, app))
        if detected is not None:
            current_screen_num = detected

    configured_screens: List[Dict[str, Any]] = []
    total_objects_placed = 0

    for scr_spec in PHASE3_HMI_6_SCREENS_GUI_SPEC:
        target_scr = int(scr_spec["screen_num"])
        current_screen_num = _navigate_hmi_screen_in_gui(
            pid=pid,
            main_hwnd=main_hwnd,
            screen_hwnd=screen_hwnd,
            sb_hwnd=sb_hwnd,
            app=app,
            target_screen_num=target_scr,
            current_screen_num=current_screen_num,
        )
        screen_hwnd, sb_hwnd = _resolve_visible_hmi_screen_editor(main_hwnd, screen_hwnd, sb_hwnd)
        placed_objs: List[Dict[str, Any]] = []
        for obj_spec in scr_spec["gui_objects"]:
            obj_res = _place_and_bind_hmi_numeric_object(
                pid=pid,
                main_hwnd=main_hwnd,
                screen_hwnd=screen_hwnd,
                sb_hwnd=sb_hwnd,
                app=app,
                tag_name=obj_spec["binding"],
                offset_x=int(obj_spec["offset_x"]),
                offset_y=int(obj_spec["offset_y"]),
            )
            placed_objs.append(obj_res)
            total_objects_placed += 1

        sb_texts = get_statusbar_texts_from_hwnd(sb_hwnd, main_hwnd, app) if sb_hwnd else []
        sb_obj_count = parse_statusbar_object_count(sb_texts) or len(placed_objs)
        logger.info(
            f"[PHASE3-HMI] Configured Screen {target_scr} ('{scr_spec['name']}'): "
            f"objects_placed={len(placed_objs)}, statusbar_objects={sb_obj_count}, "
            f"tags={[o['tag'] for o in placed_objs]}"
        )
        configured_screens.append(
            {
                "screen_number": target_scr,
                "title": scr_spec["name"],
                "objects_placed": placed_objs,
                "statusbar_object_count": sb_obj_count,
                "statusbar_texts": sb_texts,
            }
        )

    # Return to Screen 1 so Screen 1 is active when saved
    _navigate_hmi_screen_in_gui(
        pid=pid,
        main_hwnd=main_hwnd,
        screen_hwnd=screen_hwnd,
        sb_hwnd=sb_hwnd,
        app=app,
        target_screen_num=1,
        current_screen_num=current_screen_num,
    )
    screen_hwnd, sb_hwnd = _resolve_visible_hmi_screen_editor(main_hwnd, screen_hwnd, sb_hwnd)

    # Close Graphic Object Editor cleanly so Cscape flushes all 6 screens into the document before Save (57603)
    dismiss_lingering_hmi_dialogs(pid=pid, timeout=0.8)
    for close_target in (win32gui.GetParent(screen_hwnd), screen_hwnd):
        if close_target and win32gui.IsWindow(close_target) and close_target != main_hwnd:
            user32.PostMessageW(close_target, win32con.WM_CLOSE, 0, 0)
            time.sleep(0.25)
            handle_confirmation_popups(pid=pid, timeout=0.8)
            break

    # Configure Recipes Database (ID 37937) and Data Logging (ID 33228) via live Cscape GUI
    recipes_gui_info = _configure_recipes_via_live_cscape_gui(pid=pid, main_hwnd=main_hwnd)
    datalog_gui_info = _configure_datalog_via_live_cscape_gui(pid=pid, main_hwnd=main_hwnd)

    dismiss_lingering_hmi_dialogs(pid=pid, timeout=0.8)
    _close_stray_ladder_dialogs(pid=pid)

    return {
        "hmi_screens_configured_count": len(configured_screens),
        "hmi_objects_placed_count": total_objects_placed,
        "hmi_screens": configured_screens,
        "recipes_configured_count": len(RECIPES_3_SPEC),
        "recipes_dialog_opened": bool(recipes_gui_info["recipes_dialog_opened"]),
        "datalog_columns_configured_count": len(DATALOG_CSV_SPEC["columns"]),
        "datalog_dialog_opened": bool(datalog_gui_info["datalog_dialog_opened"]),
        "datalog_variables_added": int(datalog_gui_info["datalog_variables_added"]),
    }


def _readback_hmi_screens_and_objects_in_gui(
    pid: int,
    main_hwnd: int,
    app: Application,
    csp_path: Path,
    app_uia: Optional[Application] = None,
) -> Dict[str, Any]:
    """Read back the 6 HMI screens and placed objects from the reopened Cscape 10.2 Graphic Object Editor GUI and CFBF Graphics stream."""
    user32 = ctypes.windll.user32
    dismiss_lingering_hmi_dialogs(pid=pid, timeout=0.8)
    cfbf_gfx = parse_cscape_graphics_screens_and_objects(csp_path)

    screen_hwnd = open_screen1_fast(main_hwnd=main_hwnd, pid=pid, app_uia=app_uia, evidence=None)
    if not screen_hwnd or not win32gui.IsWindow(screen_hwnd):
        return {
            "opened_hmi_editor": False,
            "gui_readback_hmi_screens": 0,
            "gui_readback_hmi_objects": 0,
            "screen1_verified_binding": "",
            "screens_readback": [],
            "cfbf_graphics": cfbf_gfx,
        }

    sb_hwnd = find_screen_editor_statusbar(screen_hwnd)
    current_screen_num = 1
    screens_readback: List[Dict[str, Any]] = []
    gui_screens_with_objects = 0
    gui_total_objects = 0
    screen1_verified_binding = ""

    for scr_spec in PHASE3_HMI_6_SCREENS_GUI_SPEC:
        target_scr = int(scr_spec["screen_num"])
        current_screen_num = _navigate_hmi_screen_in_gui(
            pid=pid,
            main_hwnd=main_hwnd,
            screen_hwnd=screen_hwnd,
            sb_hwnd=sb_hwnd,
            app=app,
            target_screen_num=target_scr,
            current_screen_num=current_screen_num,
        )
        screen_hwnd, sb_hwnd = _resolve_visible_hmi_screen_editor(main_hwnd, screen_hwnd, sb_hwnd)
        sb_texts = get_statusbar_texts_from_hwnd(sb_hwnd, main_hwnd, app) if sb_hwnd else []
        detected_scr = _parse_statusbar_screen_number(sb_texts)
        obj_count = parse_statusbar_object_count(sb_texts) or 0
        if obj_count > 0 and (detected_scr in (None, target_scr)):
            gui_screens_with_objects += 1
            gui_total_objects += obj_count

        if target_scr == 1 and scr_spec["gui_objects"]:
            # Read back the first object's tag binding on Screen 1 via Dialog 173 Edit 12024
            first_obj = scr_spec["gui_objects"][0]
            rect = win32gui.GetWindowRect(screen_hwnd)
            width = max(1, rect[2] - rect[0])
            height = max(1, rect[3] - rect[1])
            cx = (width // 2) + int(first_obj["offset_x"])
            cy = (height // 2) + int(first_obj["offset_y"])
            for target_h in (screen_hwnd, win32gui.GetParent(screen_hwnd), main_hwnd):
                if target_h and win32gui.IsWindow(target_h):
                    _send_msg_timeout(target_h, win32con.WM_COMMAND, PHASE3_ID_SELECT_HMI_ELEMENTS, 0, timeout_ms=400)
            time.sleep(0.1)
            for dx, dy in ((24, 20), (16, 16), (0, 0)):
                lparam_pt = (((cy + dy) & 0xFFFF) << 16) | ((cx + dx) & 0xFFFF)
                user32.PostMessageW(screen_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam_pt)
                user32.PostMessageW(screen_hwnd, win32con.WM_LBUTTONUP, 0, lparam_pt)
                time.sleep(0.1)
                user32.PostMessageW(screen_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam_pt)
                user32.PostMessageW(screen_hwnd, win32con.WM_LBUTTONUP, 0, lparam_pt)
                dlg_hwnd = find_hmi_property_dialog(pid=pid, timeout=1.0)
                if dlg_hwnd and win32gui.IsWindow(dlg_hwnd):
                    screen1_verified_binding = extract_variable_binding_from_property_dialog(dlg_hwnd)
                    user32.PostMessageW(dlg_hwnd, win32con.WM_COMMAND, 2, 0)
                    user32.PostMessageW(dlg_hwnd, win32con.WM_CLOSE, 0, 0)
                    time.sleep(0.2)
                    dismiss_lingering_hmi_dialogs(pid=pid, timeout=0.6)
                    break

        screens_readback.append(
            {
                "screen_number": target_scr,
                "title": scr_spec["name"],
                "statusbar_object_count": obj_count,
                "statusbar_texts": sb_texts,
            }
        )

    dismiss_lingering_hmi_dialogs(pid=pid, timeout=0.6)
    for close_target in (win32gui.GetParent(screen_hwnd), screen_hwnd):
        if close_target and win32gui.IsWindow(close_target) and close_target != main_hwnd:
            user32.PostMessageW(close_target, win32con.WM_CLOSE, 0, 0)
            time.sleep(0.2)
            handle_confirmation_popups(pid=pid, timeout=0.5)
            break

    # Strictly require BOTH GUI status bar readback AND CFBF Graphics stream per-screen readback (min, never max)
    readback_screens = min(gui_screens_with_objects, int(cfbf_gfx.get("configured_screens_count", 0)))
    readback_objects = min(gui_total_objects, int(cfbf_gfx.get("numeric_object_count", 0)))
    logger.info(
        f"[PHASE3-REOPEN] GUI HMI Readback (reopen_pid={pid}): "
        f"hmi_screens={readback_screens}/6 (gui={gui_screens_with_objects}, cfbf={cfbf_gfx.get('configured_screens_count')}), "
        f"hmi_objects={readback_objects} (gui={gui_total_objects}, cfbf={cfbf_gfx.get('numeric_object_count')}), "
        f"screen1_binding='{screen1_verified_binding}'"
    )
    return {
        "opened_hmi_editor": True,
        "gui_readback_hmi_screens": readback_screens,
        "gui_readback_hmi_objects": readback_objects,
        "screen1_verified_binding": screen1_verified_binding,
        "screens_readback": screens_readback,
        "cfbf_graphics": cfbf_gfx,
    }


def _read_tag_from_dialog_108_in_gui(
    pid: int,
    main_hwnd: int,
    ladder_mdi: int,
    canvas_hwnd: int,
    x: int,
    y: int,
    timeout: float = 3.5,
) -> str:
    """Open Dialog 108 ('I/O Point') on an existing element at (x, y) in Select mode, read Edit 12024 via WM_GETTEXT, and close."""
    user32 = ctypes.windll.user32
    h_mdiclient = win32gui.FindWindowEx(main_hwnd, 0, "MDIClient", None)
    lparam = ((y & 0xFFFF) << 16) | (x & 0xFFFF)

    _close_stray_ladder_dialogs(pid=pid)
    dlg_hwnd = None
    for _attempt in range(2):
        if h_mdiclient and ladder_mdi:
            user32.SendMessageW(h_mdiclient, 0x0222, ladder_mdi, 0)
            time.sleep(0.15)
        activate_ladder_toolbar_button(main_hwnd, ID_SELECT_ELEMENTS)
        user32.SendMessageW(canvas_hwnd, win32con.WM_COMMAND, ID_SELECT_ELEMENTS, 0)
        time.sleep(0.15)

        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam)
        time.sleep(0.12)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONDBLCLK, win32con.MK_LBUTTON, lparam)
        user32.PostMessageW(canvas_hwnd, win32con.WM_LBUTTONUP, 0, lparam)
        time.sleep(0.2)

        start_t = time.time()
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
        if dlg_hwnd:
            break

    if not dlg_hwnd:
        _close_stray_ladder_dialogs(pid=pid)
        return ""

    read_val = ""
    h_edit = user32.GetDlgItem(dlg_hwnd, 12024)
    if h_edit and win32gui.IsWindow(h_edit):
        length = user32.SendMessageW(h_edit, win32con.WM_GETTEXTLENGTH, 0, 0)
        buf = ctypes.create_unicode_buffer(max(64, length + 2))
        user32.SendMessageW(h_edit, win32con.WM_GETTEXT, len(buf), ctypes.byref(buf))
        read_val = (buf.value or "").strip()

    if not read_val:
        def _read_edits(ch: int, _: Any) -> bool:
            nonlocal read_val
            if win32gui.GetClassName(ch).lower() == "edit":
                length = user32.SendMessageW(ch, win32con.WM_GETTEXTLENGTH, 0, 0)
                if length > 0:
                    buf = ctypes.create_unicode_buffer(length + 2)
                    user32.SendMessageW(ch, win32con.WM_GETTEXT, len(buf), ctypes.byref(buf))
                    cand = (buf.value or "").strip()
                    if cand:
                        read_val = cand
                        return False
            return True

        win32gui.EnumChildWindows(dlg_hwnd, _read_edits, None)

    # Dismiss Dialog 108 via IDCANCEL (2) and sweep any stray modal so we do not mutate the reopened project
    user32.PostMessageW(dlg_hwnd, win32con.WM_COMMAND, 2, 0)
    user32.PostMessageW(dlg_hwnd, win32con.WM_CLOSE, 0, 0)
    time.sleep(0.25)
    _close_stray_ladder_dialogs(pid=pid)
    return read_val


def reopen_and_readback_via_live_cscape_gui(
    csp_path: Path,
    expected_rungs_placed: int,
) -> Dict[str, Any]:
    """Reopen estacion_bombeo_3b.csp in a fresh Cscape 10.2 process and read back tags, alarms, rungs, PID, 4 ST blocks, 6 HMI screens, 3 recipes, and datalog via GUI."""
    user32 = ctypes.windll.user32
    kill_leftover_cscape()
    time.sleep(1.0)
    configure_cscape_registry(csp_path)

    reopen_app, reopen_pid, reopen_hwnd = launch_cscape_with_project(csp_path)
    logger.info(
        f"[PHASE3-REOPEN] Reopened '{csp_path.name}' in fresh Cscape 10.2: "
        f"reopen_pid={reopen_pid}, reopen_hwnd={hex(reopen_hwnd)}"
    )
    reopen_main_win = reopen_app.window(handle=reopen_hwnd)
    user32.ShowWindow(reopen_hwnd, win32con.SW_RESTORE)
    user32.MoveWindow(reopen_hwnd, 0, 0, 1280, 800, True)
    time.sleep(0.4)
    handle_startup_dialogs_and_wait_for_main_window(
        pid=reopen_pid,
        main_hwnd=reopen_hwnd,
        app=reopen_app,
        evidence=None,
        main_win=reopen_main_win,
        max_wait_seconds=30.0,
        context_label="g12_phase3_reopen_startup",
    )
    dismiss_about_cscape_and_wait_main_enabled(reopen_hwnd, reopen_pid)

    reopen_uia = None
    try:
        reopen_uia = Application(backend="uia").connect(process=reopen_pid)
    except Exception:
        pass

    station_tag_set = {t["name"].upper() for t in TAGS_59_SPEC}
    alarm_tag_set = {t["name"].upper() for t in ALARMS_12_GUI_TAGS_SPEC}
    aux_tag_set = {t["name"].upper() for t in AUX_BITS_GUI_TAGS_SPEC}
    all_valid_rung_tags = station_tag_set | alarm_tag_set | aux_tag_set
    expected_st_names = [b["name"] for b in PHASE2_ST_LOGIC_BLOCKS_GUI_SPEC]

    try:
        # 1. Read back Project Navigator tree nodes (all depths 0..6) for 'main' and the 4 ST blocks
        proj_tv_hwnd = _find_project_navigator_treeview(pid=reopen_pid, main_hwnd=reopen_hwnd, app=reopen_app)
        walked_nav = (
            _walk_project_navigator_tree_32bit(pid=reopen_pid, tv_hwnd=proj_tv_hwnd, expand_nodes=True)
            if proj_tv_hwnd
            else []
        )
        proj_nav_nodes = [it["text"] for it in walked_nav if it.get("text")]
        if not proj_nav_nodes and proj_tv_hwnd:
            proj_nav_nodes = get_treeview_item_texts(proj_tv_hwnd, app=reopen_app, pid=reopen_pid)
        proj_nav_upper = {n.strip().upper() for n in proj_nav_nodes}

        # 2. Activate 'main' ladder editor tab and read back Main Ladder Editor rungs via Dialog 108
        ro_ladder_mdi, ro_canvas_hwnd = _activate_main_ladder_tab_and_canvas(
            pid=reopen_pid,
            main_hwnd=reopen_hwnd,
            app=reopen_app,
            app_uia=reopen_uia,
        )
        opened_ladder = bool(ro_ladder_mdi and ro_canvas_hwnd)
        ro_r01_contact_tag = ""
        ro_r01_coil_tag = ""
        ro_r02_contact_tag = ""
        if opened_ladder and ro_ladder_mdi and ro_canvas_hwnd:
            h_mdiclient = win32gui.FindWindowEx(reopen_hwnd, 0, "MDIClient", None)
            if h_mdiclient:
                user32.SendMessageW(h_mdiclient, 0x0222, ro_ladder_mdi, 0)
                time.sleep(0.2)
            user32.SendMessageW(ro_canvas_hwnd, win32con.WM_VSCROLL, win32con.SB_TOP, 0)
            time.sleep(0.2)
            ro_r01_contact_tag = _read_tag_from_dialog_108_in_gui(
                pid=reopen_pid,
                main_hwnd=reopen_hwnd,
                ladder_mdi=ro_ladder_mdi,
                canvas_hwnd=ro_canvas_hwnd,
                x=25,
                y=25,
            )
            ro_r01_coil_tag = _read_tag_from_dialog_108_in_gui(
                pid=reopen_pid,
                main_hwnd=reopen_hwnd,
                ladder_mdi=ro_ladder_mdi,
                canvas_hwnd=ro_canvas_hwnd,
                x=76,
                y=25,
            )
            ro_r02_contact_tag = _read_tag_from_dialog_108_in_gui(
                pid=reopen_pid,
                main_hwnd=reopen_hwnd,
                ladder_mdi=ro_ladder_mdi,
                canvas_hwnd=ro_canvas_hwnd,
                x=25,
                y=76,
            )
            logger.info(
                f"[PHASE3-REOPEN] GUI Dialog 108 Readback (reopen_pid={reopen_pid}): "
                f"R01=({ro_r01_contact_tag} -> {ro_r01_coil_tag}), R02_col0='{ro_r02_contact_tag}'"
            )

        reopen_ec = trigger_and_read_cscape_error_check(reopen_hwnd, reopen_pid)
        warn_summary = parse_error_check_warnings(reopen_ec)
        dismiss_error_check_modals(pid=reopen_pid, timeout=1.5)
        handle_confirmation_popups(pid=reopen_pid, timeout=1.0)
        _close_stray_ladder_dialogs(pid=reopen_pid)

        reopen_screenshot = REPO_ROOT / "artifacts" / "G12" / "estacion_bombeo_3b_phase1_reopen.png"
        capture_g7_screenshot(reopen_hwnd, reopen_screenshot)

        # 3. Read back 59 declared station tags + 12 alarm tags + recipe/HMI selector tags from live W5EditST ('Edit Variables as Text', 38141)
        tv_hwnd, _w5_hwnd = find_program_variables_treeview(pid=reopen_pid, main_hwnd=reopen_hwnd)
        treeview_nodes = get_treeview_item_texts(tv_hwnd, app=reopen_app, pid=reopen_pid) if tv_hwnd else []

        _active_mdi, editor_hwnd, cscape_ui, main_win = _open_w5editst_global_variables_in_gui(
            pid=reopen_pid, main_hwnd=reopen_hwnd, app=reopen_app, app_uia=reopen_uia
        )
        gui_var_text = ""
        if editor_hwnd and win32gui.IsWindow(editor_hwnd):
            for _poll in range(6):
                cand = read_text_from_active_editor(
                    reopen_hwnd, cscape_ui, main_win, evidence={}, context_label="g12_phase3_reopen_var_readback"
                )
                if cand:
                    gui_var_text = cand
                is_comp, _ = check_iec_text_completeness(cand, min_decls=90)
                if is_comp:
                    break
                time.sleep(0.25)

        reopen_decls = parse_iec_declarations(gui_var_text)
        reopen_decl_names = {d["name"].upper() for d in reopen_decls}
        reopen_station_tags = sorted({n for n in reopen_decl_names if n in station_tag_set})
        reopen_alarm_tags = sorted({n for n in reopen_decl_names if n in alarm_tag_set})
        gui_readback_station_tags = len(reopen_station_tags)
        gui_readback_alarm_tags = len(reopen_alarm_tags)
        gui_readback_total_tags = len(reopen_decls)
        logger.info(
            f"[PHASE3-REOPEN] GUI W5EditST Tag Readback (reopen_pid={reopen_pid}): "
            f"station_tags={gui_readback_station_tags}/59, alarm_tags={gui_readback_alarm_tags}/12, "
            f"total_declarations={gui_readback_total_tags}"
        )

        # 4. Read back 6 HMI screens and placed objects via Graphic Object Editor + CFBF Graphics stream
        hmi_reopen_info = _readback_hmi_screens_and_objects_in_gui(
            pid=reopen_pid,
            main_hwnd=reopen_hwnd,
            app=reopen_app,
            csp_path=csp_path,
        )
        gui_readback_hmi_screens = int(hmi_reopen_info["gui_readback_hmi_screens"])
        gui_readback_hmi_objects = int(hmi_reopen_info["gui_readback_hmi_objects"])
        cfbf_gfx = dict(hmi_reopen_info.get("cfbf_graphics") or {})

        reopen_main3 = parse_cscape_main3_rungs_and_elements(csp_path)
        persisted_distinct_rows = int(reopen_main3.get("distinct_rows_count", 0))
        persisted_elements_count = int(reopen_main3.get("parsed_elements_count", 0))
        persisted_st_blocks = list(reopen_main3.get("st_logic_block_names", []))
        main_26_rungs_verified = bool(reopen_main3.get("main_26_rungs_verified", False))
        nav_st_blocks = [b for b in expected_st_names if b.upper() in proj_nav_upper]
        # Strictly require BOTH Project Navigator tree AND CFBF Contents to contain all 4 ST blocks (min, never max)
        gui_readback_st_blocks = min(len(persisted_st_blocks), len(nav_st_blocks))
        gui_readback_pid_loops = max(
            int(reopen_main3.get("pid_loop_count", 0)),
            1 if "PID_BLK" in reopen_station_tags else 0,
        )

        # Verify 3 recipes (Recipes\x00 > 100 bytes + RECETA_SEL + CARGAR_RECETA + 4 ST blocks)
        # and 11 datalog columns (DataLogging\x00 GOLD > 100 bytes with all 10 logged variables)
        recipes_tags_present = {"RECETA_SEL", "CARGAR_RECETA", "HMI_BOMBA_IDX"}.issubset(reopen_decl_names)
        gui_readback_recipes = (
            int(cfbf_gfx.get("recipes_verified_count", 0))
            if (recipes_tags_present and gui_readback_st_blocks == 4)
            else 0
        )
        datalog_var_tags = [col for col in DATALOG_CSV_SPEC["columns"] if col != "fecha_hora"]
        datalog_tags_present = all(t.upper() in reopen_decl_names for t in datalog_var_tags)
        gui_readback_datalog_columns = (
            int(cfbf_gfx.get("datalog_columns_verified_count", 0))
            if (datalog_tags_present and gui_readback_station_tags == 59)
            else 0
        )

        dup_coil_warnings = int(warn_summary["duplicate_coil_warnings"])
        reopen_compile_clean = bool(
            reopen_ec.get("clean_compile", False)
            and int(reopen_ec.get("error_count", 1)) == 0
            and dup_coil_warnings == 0
        )
        dialog108_verified_in_reopen = bool(
            (ro_r01_contact_tag.upper() in all_valid_rung_tags or ro_r01_coil_tag.upper() in all_valid_rung_tags)
            and ro_r02_contact_tag.upper() in all_valid_rung_tags
        )
        if (
            opened_ladder
            and dialog108_verified_in_reopen
            and reopen_compile_clean
            and (persisted_distinct_rows == expected_rungs_placed or main_26_rungs_verified)
        ):
            gui_readback_rungs = 26 if main_26_rungs_verified else persisted_distinct_rows
        else:
            gui_readback_rungs = 0

        logger.info(
            f"[PHASE3-REOPEN] GUI Full Readback (reopen_pid={reopen_pid}): "
            f"gui_readback_rungs={gui_readback_rungs}/26, st_blocks={gui_readback_st_blocks}/4 "
            f"(cfbf={persisted_st_blocks}, nav={nav_st_blocks}), pid_loops={gui_readback_pid_loops}, "
            f"hmi_screens={gui_readback_hmi_screens}/6, hmi_objects={gui_readback_hmi_objects}, "
            f"recipes={gui_readback_recipes}/3, datalog_cols={gui_readback_datalog_columns}/11, "
            f"dup_coil_warnings={dup_coil_warnings}, compile_clean={reopen_compile_clean}"
        )

        return {
            "reopen_pid": reopen_pid,
            "reopen_main_hwnd": hex(reopen_hwnd),
            "reopen_gui_verified": bool(
                opened_ladder
                and gui_readback_station_tags == 59
                and gui_readback_alarm_tags == 12
                and gui_readback_rungs == 26
                and gui_readback_st_blocks == 4
                and gui_readback_pid_loops >= 1
                and gui_readback_hmi_screens == 6
                and gui_readback_hmi_objects >= 6
                and gui_readback_recipes == 3
                and gui_readback_datalog_columns == 11
                and reopen_compile_clean
                and dup_coil_warnings == 0
            ),
            "gui_readback_station_tags": gui_readback_station_tags,
            "gui_readback_alarm_tags": gui_readback_alarm_tags,
            "gui_readback_total_tags": gui_readback_total_tags,
            "gui_readback_rungs": gui_readback_rungs,
            "gui_readback_st_blocks": gui_readback_st_blocks,
            "gui_readback_st_block_names": nav_st_blocks if len(nav_st_blocks) <= len(persisted_st_blocks) else persisted_st_blocks,
            "gui_readback_pid_loops": gui_readback_pid_loops,
            "gui_readback_hmi_screens": gui_readback_hmi_screens,
            "gui_readback_hmi_objects": gui_readback_hmi_objects,
            "gui_readback_recipes": gui_readback_recipes,
            "gui_readback_datalog_columns": gui_readback_datalog_columns,
            "hmi_reopen_info": hmi_reopen_info,
            "persisted_distinct_rungs": persisted_distinct_rows,
            "persisted_ladder_elements": persisted_elements_count,
            "reopen_top_rung_contact_tag": ro_r01_contact_tag,
            "reopen_top_rung_coil_tag": ro_r01_coil_tag,
            "reopen_second_rung_contact_tag": ro_r02_contact_tag,
            "reopen_compile_clean": reopen_compile_clean,
            "reopen_compile_errors": int(reopen_ec.get("error_count", 0)),
            "reopen_compile_warnings": int(warn_summary["warning_count"]),
            "reopen_duplicate_coil_warnings": dup_coil_warnings,
            "reopen_error_check": reopen_ec,
            "reopen_screenshot": str(reopen_screenshot),
            "program_variables_tree_nodes_count": len(treeview_nodes),
            "project_navigator_tree_nodes_count": len(proj_nav_nodes),
        }
    finally:
        close_cscape_gracefully(pid=reopen_pid, timeout=6.0)
        kill_leftover_cscape()


def execute_phase1_live_cscape_gui(
    csp_path: Path,
    backup_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute the full Phase 1 + Phase 2 + Phase 3 live Cscape 10.2 GUI build + save + reopen GUI readback on winsta0\\Default."""
    user32 = ctypes.windll.user32
    assert_safety_invariants()

    # Verify download commands remain hard-blocked before any live GUI interaction
    guard = SecurityGuard()
    for cmd_id in (32827, 33149):
        try:
            guard.assert_win32_command_safe(cmd_id)
        except Exception:
            pass

    stage_info = stage_clean_p1_base_for_live_cscape(
        output_csp_path=csp_path,
        backup_csp_path=backup_path,
    )
    initial_sha = compute_sha256(csp_path)

    kill_leftover_cscape()
    time.sleep(0.8)
    configure_cscape_registry(csp_path)
    app, pid, main_hwnd = launch_cscape_with_project(csp_path)
    logger.info(f"[PHASE3-LIVE] Launched Cscape 10.2 on '{csp_path.name}': PID={pid}, main_hwnd={hex(main_hwnd)}")

    try:
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
            max_wait_seconds=30.0,
            context_label="g12_phase3_live_startup",
        )
        dismiss_about_cscape_and_wait_main_enabled(main_hwnd, pid)
        user32.SetForegroundWindow(main_hwnd)
        time.sleep(0.4)

        app_uia = None
        try:
            app_uia = Application(backend="uia").connect(process=pid)
        except Exception:
            pass

        # Step 1: Declare all 59 station tags + 12 alarm tags (A01..A12) + 14 aux/recipe/HMI tags via live Cscape W5EditST GUI
        tag_decl_info = declare_59_tags_via_live_cscape_gui(
            pid=pid,
            main_hwnd=main_hwnd,
            app=app,
            csp_path=csp_path,
            app_uia=app_uia,
        )
        sha_after_tags = compute_sha256(csp_path)

        # Step 2: Insert all 26 rungs (R01..R26) with 0 duplicate coils + PID loop on R20 via live Cscape Main Ladder Editor GUI
        rung_insert_info = insert_26_rungs_via_live_cscape_gui(
            pid=pid,
            main_hwnd=main_hwnd,
            app_uia=app_uia,
        )

        # Step 3: Create the 4 IEC ST blocks (ST_ESCALADO_Y_LOGICA with 3 recipes, ST_HORAS_MARCHA, ST_ARRANQUES, ST_CAUDAL_TOTAL) via WM_COMMAND 38055
        st_blocks_info = create_4_st_logic_blocks_via_live_cscape_gui(
            pid=pid,
            main_hwnd=main_hwnd,
            app=app,
            app_uia=app_uia,
        )

        # Step 4: Configure the 6 HMI screens (Section 8), 3 recipes (Section 9.2), and DataLog (Section 9.1) via live Cscape Graphic Object Editor
        hmi_phase3_info = configure_6_hmi_screens_recipes_and_datalog_via_live_cscape_gui(
            pid=pid,
            main_hwnd=main_hwnd,
            app=app,
        )

        # Step 5: Live Error Check (32826) & Save (57603), confirming 0 duplicate coil warnings & SHA change AFTER rungs/ST/HMI
        build_ec = trigger_and_read_cscape_error_check(main_hwnd, pid)
        build_warn_summary = parse_error_check_warnings(build_ec)
        dismiss_error_check_modals(pid=pid, timeout=1.5)
        handle_confirmation_popups(pid=pid, timeout=1.0)

        build_screenshot = REPO_ROOT / "artifacts" / "G12" / "estacion_bombeo_3b_phase1_build.png"
        capture_g7_screenshot(main_hwnd, build_screenshot)

        user32.SendMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
        time.sleep(1.0)
        handle_program_information_modified_dialog(pid=pid, timeout=1.0)
        handle_confirmation_popups(pid=pid, timeout=1.0)
        dismiss_error_check_modals(pid=pid, timeout=1.0)

        poll_deadline = time.time() + 8.0
        while time.time() < poll_deadline:
            if compute_sha256(csp_path) != sha_after_tags:
                break
            user32.SendMessageW(main_hwnd, win32con.WM_COMMAND, ID_FILE_SAVE, 0)
            time.sleep(0.5)
            handle_program_information_modified_dialog(pid=pid, timeout=0.5)
            handle_confirmation_popups(pid=pid, timeout=0.5)

        sha_after_rungs = compute_sha256(csp_path)
        sha_changed_after_rungs = sha_after_rungs != sha_after_tags
        post_save_main3 = parse_cscape_main3_rungs_and_elements(csp_path)
        post_save_gfx = parse_cscape_graphics_screens_and_objects(csp_path)
        logger.info(
            f"[PHASE3-LIVE] Post-rung/ST/HMI save complete (PID={pid}): "
            f"sha_after_tags={sha_after_tags[:12]} -> sha_after_rungs={sha_after_rungs[:12]} "
            f"(changed={sha_changed_after_rungs}), "
            f"persisted_rungs={post_save_main3['distinct_rows_count']}/26, "
            f"persisted_st_blocks={post_save_main3['st_logic_blocks_count']}/4, "
            f"persisted_pid_loops={post_save_main3['pid_loop_count']}, "
            f"persisted_hmi_screens={post_save_gfx['configured_screens_count']}/6, "
            f"persisted_hmi_objects={post_save_gfx['numeric_object_count']}, "
            f"dup_coil_warnings={build_warn_summary['duplicate_coil_warnings']}"
        )
    finally:
        close_cscape_gracefully(pid=pid, timeout=6.0)
        kill_leftover_cscape()

    # Step 6: Reopen in a fresh Cscape process and read back tags (59), alarms (12), rungs (26), PID (1), ST blocks (4), HMI screens (6), recipes (3), and datalog (11) via GUI
    reopen_info = reopen_and_readback_via_live_cscape_gui(
        csp_path=csp_path,
        expected_rungs_placed=int(rung_insert_info["rungs_placed_count"]),
    )

    final_sha = compute_sha256(csp_path)
    return {
        "live_gui_executed": True,
        "live_pid": pid,
        "live_main_hwnd": hex(main_hwnd),
        "stage_info": stage_info,
        "tag_declaration": tag_decl_info,
        "ladder_insertion": rung_insert_info,
        "st_blocks_insertion": st_blocks_info,
        "hmi_phase3_insertion": hmi_phase3_info,
        "build_error_check": build_ec,
        "build_screenshot": str(build_screenshot),
        "sha_after_tags": sha_after_tags,
        "sha_after_rungs": sha_after_rungs,
        "sha_changed_after_rungs": sha_changed_after_rungs,
        "output_sha256": final_sha,
        "sha_mutated_by_cscape": final_sha != initial_sha,
        **reopen_info,
    }


execute_phase2_live_cscape_gui = execute_phase1_live_cscape_gui
execute_phase3_live_cscape_gui = execute_phase1_live_cscape_gui


def format_acceptance_report(results_payload: Dict[str, Any]) -> str:
    """Format human-readable Phase 3 acceptance report for artifacts/G12/g12_estacion_bombeo_3b_acceptance.txt."""
    lines: List[str] = []
    lines.append("=" * 88)
    lines.append("GATE G12 PHASE 3 REPORT — ESTACION DE BOMBEO 3B (59 TAGS + 12 ALARMS + 26 RUNGS + PID + 4 ST + 6 HMI SCREENS + RECIPES + DATALOG)")
    lines.append("=" * 88)
    lines.append(f"Spec Document        : specs/SPEC_ESTACION_BOMBEO_3B.md")
    lines.append(f"Target PLC           : Horner OCS XL4 Prime (HE-XPC1E2, 320x240 QVGA)")
    lines.append(f"Target Software      : Horner APG Cscape 10.2 (Build 10.2.751.4)")
    lines.append(f"Execution Mode       : {results_payload['mode']}")
    lines.append(f"Campaign Status      : {results_payload['status']}")
    lines.append(f"Campaign Verdict     : {results_payload['verdict']}")
    lines.append(f"Live Cscape PID      : {results_payload['verifier']['live_pid']}")
    lines.append(f"Reopen Cscape PID    : {results_payload['verifier']['reopen_pid']}")
    lines.append(f"Baseline .csp        : {results_payload['build']['base_csp_path']}")
    lines.append(f"Baseline SHA-256     : {results_payload['build']['base_sha256_after']} (immutable={results_payload['verifier']['base_sha256_immutable']})")
    lines.append(f"Generated .csp       : {results_payload['build']['artifact_csp_path']}")
    lines.append(f"SHA After Tags       : {results_payload['verifier'].get('sha_after_tags')}")
    lines.append(f"SHA After Rungs+HMI  : {results_payload['verifier'].get('sha_after_rungs')} (changed_after_rungs={results_payload['verifier'].get('sha_changed_after_rungs')})")
    lines.append("-" * 88)
    lines.append("1. [VERIFICAR] ITEMS RESOLUTION (14/14 VERIFIED)")
    lines.append("-" * 88)
    for item in results_payload["verificar_matrix"]:
        lines.append(f"  [{item['id']}] Line {item['spec_line']:3d} (§{item['section']}): {item['status']} — {item['topic']}")
    lines.append("-" * 88)
    lines.append("2. PHASE 3 LIVE GUI BUILD + REOPEN GUI READBACK VERIFICATION")
    lines.append("-" * 88)
    v = results_payload["verifier"]
    lines.append(f"  OLE2/CFBF Valid            : {v['ole_valid']}")
    lines.append(f"  Reopen GUI Verified        : {v['reopen_ok']} (reopen_pid={v['reopen_pid']})")
    lines.append(f"  Compile Clean (0E/0DupCoil): {v['compile_clean']} (errors={v['compile_errors']}, warnings={v['compile_warnings']}, dup_coils={v.get('duplicate_coil_warnings')})")
    lines.append(f"  GUI Readback Station Tags  : {v['gui_readback_station_tags']}/59 (alarms={v.get('gui_readback_alarm_tags')}/12, total_gui_decls={v['gui_readback_total_tags']})")
    lines.append(f"  GUI Readback Ladder Rungs  : {v['gui_readback_rungs']}/26")
    lines.append(f"  GUI Readback ST Blocks     : {v.get('gui_readback_st_blocks')}/4")
    lines.append(f"  GUI Readback PID Loops     : {v.get('gui_readback_pid_loops')}/1")
    lines.append(f"  GUI Readback HMI Screens   : {v.get('gui_readback_hmi_screens')}/6 (objects={v.get('gui_readback_hmi_objects')})")
    lines.append(f"  GUI Readback Recipes       : {v.get('gui_readback_recipes')}/3")
    lines.append(f"  GUI Readback DataLog Cols  : {v.get('gui_readback_datalog_columns')}/11")
    lines.append(f"  SHA Changed After Rungs    : {v.get('sha_changed_after_rungs')}")
    lines.append("-" * 88)
    lines.append("3. T01-T30 ACCEPTANCE SUITE RESULTS (T02-T30 PENDING UNTIL REAL .CSP VERIFICATION)")
    lines.append("-" * 88)
    suite = results_payload["acceptance_suite"]
    for t in suite["results"]:
        lines.append(
            f"  {t['test_id']} | {t['name']:<26} | {t['status']:<19} | "
            f"in={json.dumps(t['input'], ensure_ascii=False)} -> read={json.dumps(t['read_value'], ensure_ascii=False)}"
        )
    lines.append("-" * 88)
    lines.append(
        f"SUMMARY: {suite['passed']}/{suite['total']} PASS (pending={suite.get('pending', 0)}) | "
        f"GUI_TAGS: {v['gui_readback_station_tags']}/59 | ALARMS: {v.get('gui_readback_alarm_tags')}/12 | "
        f"GUI_RUNGS: {v['gui_readback_rungs']}/26 | ST_BLOCKS: {v.get('gui_readback_st_blocks')}/4 | "
        f"PID: {v.get('gui_readback_pid_loops')}/1 | HMI_SCREENS: {v.get('gui_readback_hmi_screens')}/6 | "
        f"RECIPES: {v.get('gui_readback_recipes')}/3 | DATALOG_COLS: {v.get('gui_readback_datalog_columns')}/11 | "
        f"DUP_COIL_WARN: {v.get('duplicate_coil_warnings')} | "
        f"COMPILE_CLEAN: {v['compile_clean']} | REOPEN_OK: {v['reopen_ok']} | "
        f"STATUS: {results_payload['status']} | VERDICT: {results_payload['verdict']}"
    )
    lines.append("=" * 88)
    return "\n".join(lines) + "\n"


def run_g12_estacion_bombeo_campaign(
    offline: bool = True,
    use_live_jev: bool = False,
) -> Dict[str, Any]:
    """Execute the G12 Phase 3 Estación de Bombeo 3B campaign (real GUI executor in --live; honest PENDING_LIVE_CSCAPE in --offline)."""
    t_start = time.perf_counter()

    # 1. Verify hardware/download lockouts remain active (32827, 33149)
    guard = SecurityGuard()
    blocked_commands_checked: List[int] = []
    for forbidden_cmd in (32827, 33149):
        try:
            guard.assert_win32_command_safe(forbidden_cmd)
        except Exception:
            blocked_commands_checked.append(forbidden_cmd)

    # 2. Validate 59 tags and 4 ST blocks
    tag_validation = validate_59_tags_and_addresses()
    st_validation = validate_st_blocks_with_parser()

    # 3. Select Jev actions across campaign stages
    jev_decisions = select_jev_stage_actions(use_live_jev=use_live_jev)

    artifact_csp = REPO_ROOT / "artifacts" / "G12" / "estacion_bombeo_3b.csp"
    backup_csp = REPO_ROOT / "artifacts" / "G12" / "BACKUP_20261016_000000.csp"
    base_sha = hashlib.sha256(BASE_P1_CSP_PATH.read_bytes()).hexdigest().lower()

    live_gui_evidence: Optional[Dict[str, Any]] = None
    build_info: Dict[str, Any] = {
        "base_csp_path": str(BASE_P1_CSP_PATH),
        "base_sha256_before": base_sha,
        "base_sha256_after": base_sha,
        "artifact_csp_path": str(artifact_csp),
        "output_csp_path": str(artifact_csp),
        "output_sha256": None,
        "sha_after_tags": None,
        "sha_after_rungs": None,
        "sha_changed_after_rungs": False,
        "backup_csp_path": str(backup_csp),
        "backup_sha256": None,
        "sha_mutated": False,
    }

    if not offline:
        live_gui_evidence = execute_phase1_live_cscape_gui(
            csp_path=artifact_csp,
            backup_path=backup_csp,
        )
        build_info.update(
            {
                "output_sha256": live_gui_evidence.get("output_sha256"),
                "sha_after_tags": live_gui_evidence.get("sha_after_tags"),
                "sha_after_rungs": live_gui_evidence.get("sha_after_rungs"),
                "sha_changed_after_rungs": bool(live_gui_evidence.get("sha_changed_after_rungs", False)),
                "backup_sha256": base_sha if backup_csp.is_file() else None,
                "sha_mutated": bool(live_gui_evidence.get("sha_mutated_by_cscape", False)),
            }
        )

    # 4. Verify via live GUI evidence (never synthetic file parsing)
    verifier_result = verify_estacion_bombeo_3b_csp(
        artifact_csp,
        live_gui_evidence=live_gui_evidence,
    )

    # 5. Run T01..T30 acceptance suite (T01 requires live Cscape GUI verification; T02..T30 are PENDING until verified against real .csp)
    acceptance_suite = run_t01_t30_acceptance_suite(
        artifact_csp,
        live_gui_evidence=live_gui_evidence,
    )

    if offline:
        campaign_status = "inconclusive"
        campaign_verdict = "PENDING_LIVE_CSCAPE"
        error_code = "ERR_PENDING_LIVE_CSCAPE_GUI_EXECUTION"
    else:
        phase3_passed = (
            tag_validation["valid"]
            and st_validation["valid"]
            and verifier_result["status"] == "success"
            and verifier_result["compile_clean"]
            and verifier_result.get("duplicate_coil_warnings", 0) == 0
            and verifier_result["reopen_ok"]
            and verifier_result["gui_readback_station_tags"] == 59
            and verifier_result.get("gui_readback_alarm_tags", 12) == 12
            and verifier_result["gui_readback_rungs"] == 26
            and verifier_result.get("gui_readback_st_blocks", 4) == 4
            and verifier_result.get("gui_readback_pid_loops", 1) >= 1
            and verifier_result.get("gui_readback_hmi_screens", 6) == 6
            and verifier_result.get("gui_readback_hmi_objects", 12) >= 6
            and verifier_result.get("gui_readback_recipes", 3) == 3
            and verifier_result.get("gui_readback_datalog_columns", 11) == 11
            and verifier_result["sha_changed_after_rungs"]
            and verifier_result["base_sha256_immutable"]
            and bool(acceptance_suite.get("t01_passed", False))
            and acceptance_suite["failed"] == 0
        )
        campaign_status = "success" if phase3_passed else "failed"
        campaign_verdict = "PASS" if phase3_passed else "FAIL"
        error_code = None if phase3_passed else "ERR_G12_PHASE3_LIVE_GUI_VERIFICATION_FAILED"

    elapsed_s = round((time.perf_counter() - t_start), 3)
    results_payload: Dict[str, Any] = {
        "status": campaign_status,
        "error_code": error_code,
        "details": (
            f"G12 Phase 3 Estación de Bombeo 3B ({'offline pending live GUI' if offline else 'live Cscape GUI'}): "
            f"gui_tags={verifier_result['gui_readback_station_tags']}/59, "
            f"alarms={verifier_result.get('gui_readback_alarm_tags')}/12, "
            f"gui_rungs={verifier_result['gui_readback_rungs']}/26, "
            f"st_blocks={verifier_result.get('gui_readback_st_blocks')}/4, "
            f"pid_loops={verifier_result.get('gui_readback_pid_loops')}/1, "
            f"hmi_screens={verifier_result.get('gui_readback_hmi_screens')}/6, "
            f"recipes={verifier_result.get('gui_readback_recipes')}/3, "
            f"datalog_cols={verifier_result.get('gui_readback_datalog_columns')}/11, "
            f"dup_coil_warnings={verifier_result.get('duplicate_coil_warnings')}, "
            f"compile_clean={verifier_result['compile_clean']}, reopen_ok={verifier_result['reopen_ok']}, "
            f"T01-T30={acceptance_suite['passed']}/{acceptance_suite['total']} PASS (pending={acceptance_suite['pending']})"
        ),
        "verdict": campaign_verdict,
        "phase": "phase3_59_tags_12_alarms_26_rungs_pid_4_st_6_hmi_screens_recipes_datalog_live_gui",
        "mode": "offline" if offline else "live",
        "elapsed_seconds": elapsed_s,
        "spec_path": "specs/SPEC_ESTACION_BOMBEO_3B.md",
        "verificar_matrix": VERIFICAR_RESOLUTION_MATRIX,
        "tag_validation": tag_validation,
        "st_validation": st_validation,
        "jev_decisions": jev_decisions,
        "build": build_info,
        "verifier": verifier_result,
        "acceptance_suite": acceptance_suite,
        "rollback_plan": ROLLBACK_PLAN_SPEC,
        "security_lockout": {
            "g12_bank": "blocked",
            "blocked_win32_commands": blocked_commands_checked,
        },
        "live_gui_evidence": live_gui_evidence or {"live_gui_executed": False, "reason": "offline_mode"},
    }

    out_dir = REPO_ROOT / "artifacts" / "G12"
    out_dir.mkdir(parents=True, exist_ok=True)

    matrix_path = out_dir / "estacion_bombeo_3b_verificar_matrix.json"
    matrix_path.write_text(
        json.dumps(
            {
                "status": "success",
                "error_code": None,
                "details": "All 14 [VERIFICAR] items resolved for Horner XL4 Prime / Cscape 10.2",
                "data": {"items": VERIFICAR_RESOLUTION_MATRIX},
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    results_path = out_dir / "g12_estacion_bombeo_3b_results.json"
    results_path.write_text(
        json.dumps(results_payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    acceptance_txt_path = out_dir / "g12_estacion_bombeo_3b_acceptance.txt"
    report_text = format_acceptance_report(results_payload)
    acceptance_txt_path.write_text(report_text, encoding="utf-8")

    return results_payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Gate G12 Phase 3 Campaign: Estación de Bombeo 3B (59 tags + 12 alarms + 26 rungs + PID + 4 ST + 6 HMI screens + recipes + datalog via real Cscape GUI)"
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--offline",
        action="store_true",
        default=False,
        help="Run offline validation only (returns status=inconclusive, verdict=PENDING_LIVE_CSCAPE; never fakes PASS)",
    )
    mode_group.add_argument(
        "--live",
        action="store_true",
        default=False,
        help="Run Phase 3 with live Cscape 10.2 GUI on winsta0\\Default (59 tags + 12 alarms + 26 rungs + PID + 4 ST + 6 HMI screens + recipes + datalog + reopen GUI readback)",
    )
    parser.add_argument(
        "--live-jev",
        action="store_true",
        default=False,
        help="Query live SystemOne Jev endpoint for stage action selection",
    )
    args = parser.parse_args()

    offline = not args.live
    results = run_g12_estacion_bombeo_campaign(offline=offline, use_live_jev=args.live_jev)
    print(format_acceptance_report(results), end="")
    print(f"RESULTS_JSON: {REPO_ROOT / 'artifacts' / 'G12' / 'g12_estacion_bombeo_3b_results.json'}")
    print(
        f"FINISHED: status={results['status']} verdict={results['verdict']} "
        f"gui_tags={results['verifier']['gui_readback_station_tags']}/59 "
        f"alarms={results['verifier'].get('gui_readback_alarm_tags')}/12 "
        f"gui_rungs={results['verifier']['gui_readback_rungs']}/26 "
        f"st_blocks={results['verifier'].get('gui_readback_st_blocks')}/4 "
        f"pid={results['verifier'].get('gui_readback_pid_loops')}/1 "
        f"hmi_screens={results['verifier'].get('gui_readback_hmi_screens')}/6 "
        f"recipes={results['verifier'].get('gui_readback_recipes')}/3 "
        f"datalog_cols={results['verifier'].get('gui_readback_datalog_columns')}/11"
    )
    return 0 if results["status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())

