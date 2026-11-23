# -*- coding: utf-8 -*-
"""Unit and Acceptance Tests for Gate G12 Real Project (Phase 1 + Phase 2): SPEC_ESTACION_BOMBEO_3B."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from jev_cscape.estacion_bombeo_3b import (
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
    PHASE2_ID_NEW_LOGIC_BLOCK,
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
    format_59_tags_for_w5editst,
    parse_cscape_graphics_screens_and_objects,
    parse_cscape_main3_rungs_and_elements,
    run_t01_t30_acceptance_suite,
    stage_clean_p1_base_for_live_cscape,
    validate_59_tags_and_addresses,
    validate_st_blocks_with_parser,
    verify_estacion_bombeo_3b_csp,
)
from scripts.g3_edit_roundtrip import parse_iec_declarations
from scripts.g12_estacion_bombeo_campaign import (
    JEV_CAMPAIGN_STAGES,
    _assign_pid_in_dialog_325,
    _navigate_hmi_screen_in_gui,
    _parse_statusbar_screen_number,
    _place_and_bind_hmi_numeric_object,
    _place_rungs_on_active_ladder_canvas,
    _readback_hmi_screens_and_objects_in_gui,
    configure_6_hmi_screens_recipes_and_datalog_via_live_cscape_gui,
    create_4_st_logic_blocks_via_live_cscape_gui,
    declare_59_tags_via_live_cscape_gui,
    execute_phase1_live_cscape_gui,
    execute_phase2_live_cscape_gui,
    execute_phase3_live_cscape_gui,
    insert_26_rungs_via_live_cscape_gui,
    parse_error_check_warnings,
    reopen_and_readback_via_live_cscape_gui,
    run_g12_estacion_bombeo_campaign,
    select_jev_stage_actions,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_spec_file_copied_and_all_14_verificar_resolved() -> None:
    spec_path = REPO_ROOT / "specs" / "SPEC_ESTACION_BOMBEO_3B.md"
    assert spec_path.is_file(), "specs/SPEC_ESTACION_BOMBEO_3B.md must exist"
    text = spec_path.read_text(encoding="utf-8")
    assert "## 12. Resolución Técnica de Ítems `[VERIFICAR]`" in text
    assert len(VERIFICAR_RESOLUTION_MATRIX) == 14
    ids = [item["id"] for item in VERIFICAR_RESOLUTION_MATRIX]
    assert ids == [f"V{i:02d}" for i in range(1, 15)]
    for item in VERIFICAR_RESOLUTION_MATRIX:
        assert item["status"] == "VERIFIED"
        assert f"**{item['id']}**" in text


def test_59_named_tags_12_alarms_and_w5editst_formatting() -> None:
    res = validate_59_tags_and_addresses()
    assert res["valid"] is True
    assert res["total_named_tags"] == 59
    assert res["collisions"] == []
    assert res["counts_by_category"] == {
        "DI": 12,
        "DO": 5,
        "AI": 3,
        "AQ": 1,
        "REAL": 15,
        "INT": 11,
        "M": 12,
    }

    assert len(ALARMS_12_GUI_TAGS_SPEC) == 12
    assert [a["name"] for a in ALARMS_12_GUI_TAGS_SPEC] == [f"A{i:02d}" for i in range(1, 13)]
    assert {a["address"] for a in ALARMS_12_GUI_TAGS_SPEC} == {f"%M{i}" for i in range(14, 26)}
    assert len(AUX_BITS_GUI_TAGS_SPEC) == 14

    w5_text = format_59_tags_for_w5editst("VAR_GLOBAL\r\n   ALW_ON : BOOL ;\r\n      (*$tag=%S7*)\r\nEND_VAR\r\n")
    assert "PID_BLK : PID ;\r\n      (*$tag=%R100*)" in w5_text
    decls = parse_iec_declarations(w5_text)
    decl_names = {d["name"].upper() for d in decls}
    for t in TAGS_59_SPEC:
        assert t["name"].upper() in decl_names, f"Missing station tag {t['name']} in W5EditST block"
    for a in ALARMS_12_GUI_TAGS_SPEC:
        assert a["name"].upper() in decl_names, f"Missing alarm tag {a['name']} in W5EditST block"
    for aux in AUX_BITS_GUI_TAGS_SPEC:
        assert aux["name"].upper() in decl_names, f"Missing aux tag {aux['name']} in W5EditST block"
    assert len(decls) == 86  # 1 ALW_ON + 59 station tags + 12 alarm tags + 14 aux/recipe/HMI tags


def test_phase2_26_rungs_zero_duplicate_coils_pid_and_4_st_blocks() -> None:
    assert len(PHASE1_LADDER_26_RUNGS_GUI_SPEC) == 26
    assert PHASE2_LADDER_26_RUNGS_GUI_SPEC is PHASE1_LADDER_26_RUNGS_GUI_SPEC
    assert [r["rung"] for r in PHASE1_LADDER_26_RUNGS_GUI_SPEC] == [f"R{i:02d}" for i in range(1, 27)]
    assert PHASE1_ID_SELECT_ELEMENTS == 112
    assert PHASE1_ID_NO_CONTACT == 1000
    assert PHASE1_ID_NC_CONTACT == 1001
    assert PHASE1_ID_NO_COIL == 1002
    assert PHASE1_ID_SET_COIL == 142
    assert PHASE1_ID_RESET_COIL == 143
    assert PHASE1_ID_PID_IND == 155
    assert PHASE1_ID_INSERT_NEW_RUNG == 32820
    assert PHASE1_ID_INSERT_1_BLANK_LINE == 32889
    assert PHASE2_ID_NEW_LOGIC_BLOCK == 38036

    bool_tags = (
        {t["name"] for t in TAGS_59_SPEC if t["type"] == "BOOL"}
        | {a["name"] for a in ALARMS_12_GUI_TAGS_SPEC}
        | {x["name"] for x in AUX_BITS_GUI_TAGS_SPEC if x["type"] == "BOOL"}
    )
    assert len(bool_tags) == 53  # 29 station BOOL + 12 alarm BOOL + 12 aux BOOL (including CARGAR_RECETA)

    # Verify R20 is the PID loop with PID_BLK, PID_SP, PID_PV, PID_CV and 3 extra blank lines
    r20 = PHASE1_LADDER_26_RUNGS_GUI_SPEC[19]
    assert r20["rung"] == "R20"
    assert r20["coil"]["cmd"] == PHASE1_ID_PID_IND
    assert r20["coil"]["type"] == "PID_IND"
    assert r20["coil"]["tag"] == "PID_BLK"
    assert r20["coil"]["sp_tag"] == "PID_SP"
    assert r20["coil"]["pv_tag"] == "PID_PV"
    assert r20["coil"]["cv_tag"] == "PID_CV"
    assert r20["coil"]["extra_blank_lines"] == 3

    # Verify all 4 ST / Logic blocks exist and match spec Section 5
    assert len(PHASE2_ST_LOGIC_BLOCKS_GUI_SPEC) == 4
    assert [b["name"] for b in PHASE2_ST_LOGIC_BLOCKS_GUI_SPEC] == [
        "ST_ESCALADO_Y_LOGICA",
        "ST_HORAS_MARCHA",
        "ST_ARRANQUES",
        "ST_CAUDAL_TOTAL",
    ]
    st_val = validate_st_blocks_with_parser()
    assert st_val["valid"] is True
    assert st_val["block_count"] == 4

    # Verify ZERO duplicate coil warnings across R01..R26 (especially rungs 4, 8, 9, 17, 21, 23, 26)
    # In Cscape 10.2 (0x0059cf00), any COIL_NO (1002) tag must NEVER appear in any other COIL_NO, COIL_SET, or COIL_RESET
    # anywhere in main or in the 4 ST/logic blocks!
    no_coil_tags: list[str] = []
    set_reset_coil_tags: list[str] = []
    all_rungs = list(PHASE1_LADDER_26_RUNGS_GUI_SPEC)
    for blk in PHASE2_ST_LOGIC_BLOCKS_GUI_SPEC:
        all_rungs.extend(blk["rungs"])

    for r in all_rungs:
        for c in r["contacts"]:
            assert c["cmd"] in (PHASE1_ID_NO_CONTACT, PHASE1_ID_NC_CONTACT)
            assert c["tag"] in bool_tags, f"{r['rung']} contact {c['tag']} is not a declared BOOL"
        coil = r["coil"]
        if coil["cmd"] == PHASE1_ID_PID_IND:
            assert coil["tag"] == "PID_BLK"
            fb = coil.get("fallback_coil")
            if fb:
                set_reset_coil_tags.append(fb["tag"])
        elif coil["cmd"] == PHASE1_ID_NO_COIL:
            assert coil["tag"] in bool_tags
            no_coil_tags.append(coil["tag"])
        else:
            assert coil["cmd"] in (PHASE1_ID_SET_COIL, PHASE1_ID_RESET_COIL)
            assert coil["tag"] in bool_tags
            set_reset_coil_tags.append(coil["tag"])

    assert len(no_coil_tags) == len(set(no_coil_tags)), f"Duplicate COIL_NO tags: {no_coil_tags}"
    overlap_with_set_reset = set(no_coil_tags) & set(set_reset_coil_tags)
    assert overlap_with_set_reset == set(), (
        f"COIL_NO tags also used in COIL_SET/COIL_RESET would trigger 'Warn : Duplicate coil' in Cscape: {overlap_with_set_reset}"
    )

    # Specifically verify rungs 4, 8, 9, 17, 21, 23, 26 have unique coil tags
    for r_num in (4, 8, 9, 17, 21, 23, 26):
        rung_spec = PHASE1_LADDER_26_RUNGS_GUI_SPEC[r_num - 1]
        c_tag = rung_spec["coil"]["tag"]
        assert no_coil_tags.count(c_tag) == 1, f"Rung {r_num} coil {c_tag} is not unique"
        assert c_tag not in set_reset_coil_tags, f"Rung {r_num} coil {c_tag} conflicts with SET/RESET coil"

    # Verify all 12 alarms A01..A12 are bound in main + 4 ST blocks
    bound_tags: set[str] = set()
    for r in all_rungs:
        for c in r["contacts"]:
            bound_tags.add(c["tag"])
        bound_tags.add(r["coil"]["tag"])
        if r["coil"].get("fallback_coil"):
            bound_tags.add(r["coil"]["fallback_coil"]["tag"])
    for i in range(1, 13):
        assert f"A{i:02d}" in bound_tags, f"Alarm A{i:02d} not bound in ladder/ST blocks"


def test_parse_error_check_warnings_detects_warn_colon_and_duplicate_coils() -> None:
    sample_ec = {
        "clean_compile": True,
        "error_count": 0,
        "warning_count": 0,
        "full_result_text": (
            "Compiling ...[estacion_bombeo_3b.csp]\n"
            "Warn : Duplicate coil at (B, 1) \tModule :main\tTile(D, 4)\tRung 4\n"
            "Warn : Duplicate coil at (B, 1) \tModule :main\tTile(D, 8)\tRung 8\n"
            "estacion_bombeo_3b.csp - 0 error(s), 0 warning(s)"
        ),
    }
    parsed = parse_error_check_warnings(sample_ec)
    assert parsed["duplicate_coil_warnings"] == 2
    assert parsed["warning_count"] == 2
    assert sample_ec["duplicate_coil_warnings"] == 2
    assert sample_ec["warning_count"] == 2


def test_anti_synthetic_audit_zero_byte_appending() -> None:
    engine_src = (REPO_ROOT / "src" / "jev_cscape" / "estacion_bombeo_3b" / "station_engine.py").read_text(
        encoding="utf-8"
    )
    campaign_src = (REPO_ROOT / "scripts" / "g12_estacion_bombeo_campaign.py").read_text(encoding="utf-8")

    forbidden_markers = [
        "G12_ESTACION_BOMBEO_3B_BEGIN",
        "G12_ESTACION_BOMBEO_3B_END",
        "build_estacion_bombeo_3b_csp_from_p1_base",
        "raw_file.extend",
    ]
    for marker in forbidden_markers:
        assert marker not in engine_src, f"Forbidden synthetic marker '{marker}' found in station_engine.py"
        assert marker not in campaign_src, f"Forbidden synthetic marker '{marker}' found in g12_estacion_bombeo_campaign.py"


def test_real_live_gui_helper_signatures_match() -> None:
    from scripts.g3_edit_roundtrip import (
        close_cscape_gracefully,
        configure_cscape_registry,
        get_treeview_item_texts,
        handle_startup_dialogs_and_wait_for_main_window,
        launch_cscape_with_project,
        read_text_from_active_editor,
    )
    from scripts.g7_acceptance import (
        dismiss_about_cscape_and_wait_main_enabled,
        trigger_and_read_cscape_error_check,
    )
    from scripts.g7_campaign import (
        activate_ladder_toolbar_button,
        assign_tag_in_dialog,
        open_main_ladder_editor,
        resolve_ladder_canvas,
    )
    from scripts.g8_acceptance import handle_confirmation_popups
    from scripts.g9_campaign import (
        _set_clipboard_unicode_text,
        close_and_commit_iec_variables_editor_tab,
        dismiss_error_check_modals,
        handle_program_information_modified_dialog,
    )
    from scripts.g10_campaign import declare_variables_via_live_cscape_win32

    assert "tv_hwnd" in inspect.signature(get_treeview_item_texts).parameters
    assert "pid" in inspect.signature(handle_confirmation_popups).parameters
    assert "pid" in inspect.signature(dismiss_error_check_modals).parameters
    assert "pid" in inspect.signature(handle_program_information_modified_dialog).parameters
    assert "text" in inspect.signature(_set_clipboard_unicode_text).parameters

    assert "project_path" in inspect.signature(configure_cscape_registry).parameters
    assert "project_path" in inspect.signature(launch_cscape_with_project).parameters
    assert "main_hwnd" in inspect.signature(handle_startup_dialogs_and_wait_for_main_window).parameters
    assert "main_hwnd" in inspect.signature(dismiss_about_cscape_and_wait_main_enabled).parameters
    assert list(inspect.signature(declare_variables_via_live_cscape_win32).parameters.keys())[:4] == [
        "pid",
        "main_hwnd",
        "app",
        "spec",
    ]
    assert "main_hwnd" in inspect.signature(read_text_from_active_editor).parameters
    assert "editor_hwnd" in inspect.signature(close_and_commit_iec_variables_editor_tab).parameters
    assert "main_hwnd" in inspect.signature(open_main_ladder_editor).parameters
    assert "main_hwnd" in inspect.signature(resolve_ladder_canvas).parameters
    assert list(inspect.signature(activate_ladder_toolbar_button).parameters.keys()) == ["main_hwnd", "cmd_id"]
    assert list(inspect.signature(assign_tag_in_dialog).parameters.keys())[:2] == ["pid", "tag_name"]
    assert list(inspect.signature(trigger_and_read_cscape_error_check).parameters.keys())[:2] == ["main_hwnd", "pid"]
    assert "pid" in inspect.signature(close_cscape_gracefully).parameters

    # Verify Phase 2 campaign functions exist and wire into the real GUI helpers
    assert execute_phase2_live_cscape_gui is execute_phase1_live_cscape_gui
    campaign_src = inspect.getsource(execute_phase1_live_cscape_gui)
    assert "launch_cscape_with_project" in campaign_src
    assert "declare_59_tags_via_live_cscape_gui" in campaign_src
    assert "insert_26_rungs_via_live_cscape_gui" in campaign_src
    assert "create_4_st_logic_blocks_via_live_cscape_gui" in campaign_src
    assert "trigger_and_read_cscape_error_check" in campaign_src
    assert "parse_error_check_warnings" in campaign_src
    assert "reopen_and_readback_via_live_cscape_gui" in campaign_src
    assert "sha_changed_after_rungs" in campaign_src

    decl_src = inspect.getsource(declare_59_tags_via_live_cscape_gui)
    assert "declare_variables_via_live_cscape_win32" in decl_src
    assert "close_and_commit_iec_variables_editor_tab" in decl_src

    rung_src = inspect.getsource(_place_rungs_on_active_ladder_canvas)
    assert "PHASE1_ID_INSERT_NEW_RUNG" in rung_src
    assert "PHASE1_ID_INSERT_1_BLANK_LINE" in rung_src
    assert "PHASE1_ID_PID_IND" in rung_src
    assert "_assign_pid_in_dialog_325" in rung_src
    assert "activate_ladder_toolbar_button" in rung_src
    assert "assign_tag_in_dialog" in rung_src

    st_src = inspect.getsource(create_4_st_logic_blocks_via_live_cscape_gui)
    assert "PHASE2_ID_NEW_IEC_ST_BLOCK" in st_src
    assert "PHASE2_ID_RENAME_MODULE" in st_src
    assert "_activate_main_ladder_tab_and_canvas" in st_src
    assert "_place_rungs_on_active_ladder_canvas" in st_src

    reopen_src = inspect.getsource(reopen_and_readback_via_live_cscape_gui)
    assert "launch_cscape_with_project" in reopen_src
    assert "parse_iec_declarations" in reopen_src
    assert "_activate_main_ladder_tab_and_canvas" in reopen_src
    assert "_walk_project_navigator_tree_32bit" in reopen_src
    assert "_read_tag_from_dialog_108_in_gui" in reopen_src
    assert "parse_cscape_main3_rungs_and_elements" in reopen_src
    assert "trigger_and_read_cscape_error_check" in reopen_src
    assert "parse_error_check_warnings" in reopen_src
    assert "close_and_commit_iec_variables_editor_tab(" not in reopen_src


def test_offline_mode_never_fakes_pass_or_creates_synthetic_csp(tmp_path: Path) -> None:
    decisions = select_jev_stage_actions(use_live_jev=False)
    assert len(decisions) == len(JEV_CAMPAIGN_STAGES) == 4
    assert all(d["match"] is True for d in decisions)

    # Without live GUI evidence, verifier and campaign MUST return inconclusive / PENDING_LIVE_CSCAPE
    non_existent = tmp_path / "estacion_bombeo_3b.csp"
    ver_offline = verify_estacion_bombeo_3b_csp(non_existent, live_gui_evidence=None)
    assert ver_offline["status"] == "inconclusive"
    assert ver_offline["verdict"] == "PENDING_LIVE_CSCAPE"
    assert ver_offline["compile_clean"] is False
    assert ver_offline["reopen_ok"] is False
    assert ver_offline["gui_readback_station_tags"] == 0
    assert ver_offline["gui_readback_rungs"] == 0

    campaign_res = run_g12_estacion_bombeo_campaign(offline=True, use_live_jev=False)
    assert campaign_res["status"] == "inconclusive"
    assert campaign_res["verdict"] == "PENDING_LIVE_CSCAPE"
    assert campaign_res["verifier"]["compile_clean"] is False
    assert campaign_res["acceptance_suite"]["status"] == "inconclusive"
    assert campaign_res["acceptance_suite"]["passed"] == 0
    assert campaign_res["acceptance_suite"]["pending"] == 30
    t01 = campaign_res["acceptance_suite"]["results"][0]
    assert t01["test_id"] == "T01"
    assert t01["status"] == "PENDING"
    assert t01["verdict"] == "PENDING_LIVE_CSCAPE"
    assert t01["passed"] is False
    for row in campaign_res["acceptance_suite"]["results"][1:]:
        assert row["status"] == "PENDING"
        assert row["verdict"] == "PENDING"
        assert row["passed"] is False


def test_verifier_and_t01_t30_pending_policy_with_authentic_live_gui_readback(tmp_path: Path) -> None:
    staged_csp = tmp_path / "estacion_bombeo_3b.csp"
    stage_info = stage_clean_p1_base_for_live_cscape(staged_csp)
    assert staged_csp.is_file()
    assert stage_info["base_sha256_after"] == BASELINE_P1_SHA256

    # Verify baseline p1_base.csp has 0 rungs in main3 stream
    base_main3 = parse_cscape_main3_rungs_and_elements(staged_csp)
    assert base_main3["valid"] is True
    assert base_main3["rung_count"] == 0
    assert base_main3["total_elements"] == 0

    # Simulate Cscape saving a modified OLE2 stream during a real live session
    data = bytearray(staged_csp.read_bytes())
    data[-16:] = b"CSCAPE_SAVE_10_2"
    staged_csp.write_bytes(bytes(data))

    live_evidence = {
        "live_gui_executed": True,
        "live_pid": 14520,
        "reopen_pid": 18940,
        "reopen_gui_verified": True,
        "sha_changed_after_rungs": True,
        "gui_readback_station_tags": 59,
        "gui_readback_alarm_tags": 12,
        "gui_readback_total_tags": 105,
        "gui_readback_rungs": 26,
        "gui_readback_st_blocks": 4,
        "gui_readback_pid_loops": 1,
        "reopen_compile_clean": True,
        "reopen_compile_errors": 0,
        "reopen_compile_warnings": 0,
        "reopen_duplicate_coil_warnings": 0,
    }
    ver = verify_estacion_bombeo_3b_csp(staged_csp, live_gui_evidence=live_evidence)
    assert ver["status"] == "success"
    assert ver["verdict"] == "PASS"
    assert ver["compile_clean"] is True
    assert ver["duplicate_coil_warnings"] == 0
    assert ver["reopen_ok"] is True
    assert ver["sha_changed_after_rungs"] is True
    assert ver["gui_readback_station_tags"] == 59
    assert ver["gui_readback_alarm_tags"] == 12
    assert ver["gui_readback_rungs"] == 26
    assert ver["gui_readback_st_blocks"] == 4
    assert ver["gui_readback_pid_loops"] == 1
    assert ver["live_pid"] == 14520
    assert ver["reopen_pid"] == 18940

    # Verify duplicate coil warnings fail closed in verifier
    bad_dup_evidence = dict(live_evidence, reopen_duplicate_coil_warnings=7)
    ver_dup = verify_estacion_bombeo_3b_csp(staged_csp, live_gui_evidence=bad_dup_evidence)
    assert ver_dup["status"] == "failed"
    assert ver_dup["verdict"] == "FAIL"

    # T01 passes when Phase 2 live GUI verification succeeds; T02..T30 remain PENDING until verified against real .csp
    suite = run_t01_t30_acceptance_suite(staged_csp, live_gui_evidence=live_evidence)
    assert suite["status"] == "inconclusive"
    assert suite["passed"] == 1
    assert suite["pending"] == 29
    assert suite["failed"] == 0
    assert suite["results"][0]["test_id"] == "T01"
    assert suite["results"][0]["status"] == "PASS"
    assert suite["results"][0]["passed"] is True
    for row in suite["results"][1:]:
        assert row["status"] == "PENDING"
        assert row["verdict"] == "PENDING"
        assert row["passed"] is False


def test_bootstrap_tag_replacement_in_format_59_tags() -> None:
    """Verify bootstrap tags added by declare_variables_via_live_cscape_win32 are replaced with canonical addresses."""
    bootstrapped = (
        "VAR\r\n"
        "   ALW_ON : BOOL ;\r\n"
        "      (*$tag=%S007*)\r\n"
        "   P1_ARRANQUES : INT ;\r\n"
        "      (*$tag=%R101*)\r\n"
        "   P1_FB_MARCHA : BOOL ;\r\n"
        "      (*$tag=%M101*)\r\n"
        "END_VAR\r\n"
    )
    updated = format_59_tags_for_w5editst(bootstrapped)
    assert "(*$tag=%R101*)" not in updated
    assert "(*$tag=%M101*)" not in updated
    p1_arr_addr = next(t["address"] for t in TAGS_59_SPEC if t["name"] == "P1_ARRANQUES")
    assert f"P1_ARRANQUES : INT ;\r\n      (*$tag={p1_arr_addr}*)" in updated
    assert "P1_FB_MARCHA : BOOL ;\r\n      (*$tag=%I1*)" in updated
    decls = parse_iec_declarations(updated)
    assert len(decls) == 86  # 1 ALW_ON + 59 station + 12 alarms + 14 aux/recipe/HMI tags


def test_phase3_6_hmi_screens_3_recipes_and_11_datalog_columns_and_gui_readback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify Phase 3: 6 HMI screens (Section 8), 3 recipes (Section 9.2), 11 datalog columns (Section 9.1), and live GUI readback."""
    import scripts.g12_estacion_bombeo_campaign as g12_mod

    # 1. Verify Phase 3 command IDs and 6 HMI screens spec
    assert PHASE3_ID_INSERT_NUMERIC_DATA == 7610
    assert PHASE3_ID_SELECT_HMI_ELEMENTS == 7655
    assert PHASE3_ID_GOTO_NEXT_SCREEN == 7661
    assert PHASE3_ID_GOTO_PREV_SCREEN == 7662
    assert PHASE3_ID_GOTO_SCREEN_DLG == 2832
    assert PHASE3_ID_DATALOG_CONFIG == 33228
    assert PHASE3_ID_RECIPES_CONFIG == 37937
    assert execute_phase3_live_cscape_gui is execute_phase1_live_cscape_gui

    assert len(HMI_6_SCREENS_SPEC) == 6
    assert len(PHASE3_HMI_6_SCREENS_GUI_SPEC) == 6
    assert [s["screen_num"] for s in PHASE3_HMI_6_SCREENS_GUI_SPEC] == [1, 2, 3, 4, 5, 6]

    declared_upper = (
        {t["name"].upper() for t in TAGS_59_SPEC}
        | {a["name"].upper() for a in ALARMS_12_GUI_TAGS_SPEC}
        | {x["name"].upper() for x in AUX_BITS_GUI_TAGS_SPEC}
    )
    total_hmi_objs = 0
    for scr in PHASE3_HMI_6_SCREENS_GUI_SPEC:
        assert len(scr["gui_objects"]) >= 2
        for obj in scr["gui_objects"]:
            total_hmi_objs += 1
            assert obj["cmd"] == PHASE3_ID_INSERT_NUMERIC_DATA
            assert obj["binding"].upper() in declared_upper
            # Verify offsets stay inside the centered 320x240 XL4 Prime screen area
            assert -120 <= int(obj["offset_x"]) <= 120
            assert -90 <= int(obj["offset_y"]) <= 90
    assert total_hmi_objs == 12

    # 2. Verify 3 recipes (Normal, Demanda alta, Ahorro nocturno) in RECIPES_3_SPEC and ST_ESCALADO_Y_LOGICA
    assert len(RECIPES_3_SPEC) == 3
    assert list(RECIPES_3_SPEC.keys()) == ["Normal", "Demanda alta", "Ahorro nocturno"]
    st_escalado = ST_BLOCKS_SOURCE["ST_ESCALADO_Y_LOGICA"]
    assert "IF CARGAR_RECETA THEN" in st_escalado
    assert "IF RECETA_SEL = 1 THEN" in st_escalado
    assert "ELSIF RECETA_SEL = 2 THEN" in st_escalado
    assert "ELSIF RECETA_SEL = 3 THEN" in st_escalado
    assert "CARGAR_RECETA := FALSE;" in st_escalado
    assert "IF HMI_BOMBA_IDX < 1 OR HMI_BOMBA_IDX > 3 THEN" in st_escalado

    # 3. Verify 11 datalog columns (fecha_hora + 10 declared station variables)
    assert len(DATALOG_CSV_SPEC["columns"]) == 11
    assert DATALOG_CSV_SPEC["sample_period_s"] == 60.0
    assert DATALOG_CSV_SPEC["non_blocking_if_sd_missing"] is True
    for col in DATALOG_CSV_SPEC["columns"]:
        if col != "fecha_hora":
            assert col.upper() in declared_upper, f"Datalog column {col} not in declared tags"

    # 4. Verify _parse_statusbar_screen_number and CFBF Graphics parser on baseline p1_base.csp
    assert _parse_statusbar_screen_number(["", "", "Screen: 1*", "Zoom: 120%", "2 Objects"]) == 1
    assert _parse_statusbar_screen_number(["", "Screen: 6", "1 Objects"]) == 6
    assert _parse_statusbar_screen_number(["Zoom: 100%"]) is None

    staged_csp = tmp_path / "estacion_bombeo_3b.csp"
    stage_clean_p1_base_for_live_cscape(staged_csp)
    gfx_base = parse_cscape_graphics_screens_and_objects(staged_csp)
    assert gfx_base["valid"] is True
    assert gfx_base["graphics_section_present"] is True
    assert gfx_base["datalog_section_present"] is True
    # Unconfigured baseline p1_base.csp must report 0 configured screens, 0 recipes, and 0 datalog columns (GOLN disabled)
    assert gfx_base["configured_screens_count"] == 0
    assert gfx_base["recipes_verified_count"] == 0
    assert gfx_base["datalog_columns_verified_count"] == 0
    assert gfx_base["datalog_enabled"] is False
    assert gfx_base["recipes_section_configured"] is False

    # Verify parse_error_check_warnings detects 'Fatal:' graphics errors (such as unbound object at 112, 126)
    fatal_ec = {
        "clean_compile": True,
        "error_count": 0,
        "warning_count": 0,
        "full_result_text": (
            "Compiling Logic...\r\n"
            "0 Resulting Errors\r\n"
            "0 Resulting Warnings\r\n"
            "Compiling Graphics...\r\n"
            "Fatal: Data Source - Invalid I/O assignment.Screen 1 at ( 112 , 126 ) - Double click here for location.\r\n"
        ),
    }
    fatal_summary = parse_error_check_warnings(fatal_ec)
    assert fatal_summary["error_count"] == 1
    assert len(fatal_summary["fatal_error_lines"]) == 1
    assert fatal_ec["error_count"] == 1
    assert fatal_ec["clean_compile"] is False

    # Verify interior double-click offset (24, 20) is tried first in _place_and_bind_hmi_numeric_object,
    # Goto Screen (2832) is used in _navigate_hmi_screen_in_gui, and min() is used in reopen readback
    place_src = inspect.getsource(_place_and_bind_hmi_numeric_object)
    assert "(24, 20)" in place_src
    nav_src = inspect.getsource(_navigate_hmi_screen_in_gui)
    assert "PHASE3_ID_GOTO_SCREEN_DLG" in nav_src
    assert "1111" in nav_src
    st_src = inspect.getsource(create_4_st_logic_blocks_via_live_cscape_gui)
    assert "PHASE2_ID_NEW_LOGIC_BLOCK" in st_src
    assert "new_st_cmd" in st_src
    reopen_src = inspect.getsource(reopen_and_readback_via_live_cscape_gui)
    assert "min(len(persisted_st_blocks), len(nav_st_blocks))" in reopen_src
    hmi_ro_src = inspect.getsource(_readback_hmi_screens_and_objects_in_gui)
    assert 'min(gui_screens_with_objects, int(cfbf_gfx.get("configured_screens_count", 0)))' in hmi_ro_src

    # 5. Verify _place_and_bind_hmi_numeric_object binds Edit 12024 in Dialog 173 and sends EN_UPDATE/EN_CHANGE
    screen_hwnd = 0x700100
    dlg173_hwnd = 0x173000
    edit12024_hwnd = 0x173200
    ok173_hwnd = 0x173001
    settext_val: dict[int, str] = {}
    en_notified: list[int] = []

    monkeypatch.setattr(g12_mod, "dismiss_lingering_hmi_dialogs", lambda pid, timeout=0.8: 0)
    monkeypatch.setattr(g12_mod, "handle_confirmation_popups", lambda pid, timeout=0.6: 0)
    monkeypatch.setattr(g12_mod, "find_hmi_property_dialog", lambda pid, timeout=1.0: dlg173_hwnd)
    monkeypatch.setattr(
        g12_mod,
        "get_statusbar_texts_from_hwnd",
        lambda sb, main_h, app: ["", "Screen: 1*", "2 Objects"],
    )
    # Use the exact live rect [446, 172, 1268, 558] where client cx = (822 // 2) - 60 = 351 < 446,
    # proving screen coord tx = 446 + 351 = 797 is passed to validate_canvas_coordinates while client (351, 178) is posted!
    monkeypatch.setattr(g12_mod.win32gui, "GetWindowRect", lambda h: (446, 172, 1268, 558))
    monkeypatch.setattr(g12_mod.win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(g12_mod.win32gui, "GetParent", lambda h: dlg173_hwnd)

    class _FakeHmiUser32:
        def GetDlgItem(self, h: int, cid: int) -> int:
            if h == dlg173_hwnd and cid == 12024:
                return edit12024_hwnd
            if h == dlg173_hwnd and cid == 1:
                return ok173_hwnd
            return 0

        def SendMessageW(self, h: int, msg: int, wparam: int, lparam: object) -> int:
            if msg == g12_mod.win32con.WM_SETTEXT:
                settext_val[h] = str(lparam)
            elif msg == g12_mod.win32con.WM_GETTEXTLENGTH:
                return len(settext_val.get(h, ""))
            elif msg == g12_mod.win32con.WM_GETTEXT:
                val = settext_val.get(h, "")
                # Write into ctypes unicode buffer via its _obj
                buf_obj = getattr(lparam, "_obj", None)
                if buf_obj is not None:
                    buf_obj.value = val
                return len(val)
            elif msg == g12_mod.win32con.WM_COMMAND and ((int(wparam) >> 16) & 0xFFFF) in (0x0300, 0x0400):
                en_notified.append((int(wparam) >> 16) & 0xFFFF)
            return 1

        def PostMessageW(self, h: int, msg: int, wparam: int, lparam: object) -> int:
            return 1

    monkeypatch.setattr(g12_mod.ctypes.windll, "user32", _FakeHmiUser32())
    res_obj = _place_and_bind_hmi_numeric_object(
        pid=9999,
        main_hwnd=0x100000,
        screen_hwnd=screen_hwnd,
        sb_hwnd=0x700200,
        app=None,  # type: ignore[arg-type]
        tag_name="NIVEL_PCT",
        offset_x=-60,
        offset_y=-15,
    )
    assert res_obj["bound_ok"] is True
    assert res_obj["readback_tag"] == "NIVEL_PCT"
    assert res_obj["client_coords"] == (351, 178)
    assert res_obj["screen_coords"] == (797, 350)
    assert settext_val[edit12024_hwnd] == "NIVEL_PCT"
    assert 0x0400 in en_notified and 0x0300 in en_notified

    # 6. Verify verifier fails closed if HMI screens < 6
    data = bytearray(staged_csp.read_bytes())
    data[-16:] = b"CSCAPE_SAVE_10_2"
    staged_csp.write_bytes(bytes(data))
    bad_hmi_evidence = {
        "live_gui_executed": True,
        "live_pid": 14520,
        "reopen_pid": 18940,
        "reopen_gui_verified": True,
        "sha_changed_after_rungs": True,
        "gui_readback_station_tags": 59,
        "gui_readback_alarm_tags": 12,
        "gui_readback_total_tags": 105,
        "gui_readback_rungs": 26,
        "gui_readback_st_blocks": 4,
        "gui_readback_pid_loops": 1,
        "gui_readback_hmi_screens": 1,
        "gui_readback_hmi_objects": 2,
        "gui_readback_recipes": 3,
        "gui_readback_datalog_columns": 11,
        "reopen_compile_clean": True,
        "reopen_compile_errors": 0,
        "reopen_compile_warnings": 0,
        "reopen_duplicate_coil_warnings": 0,
    }
    ver_bad_hmi = verify_estacion_bombeo_3b_csp(staged_csp, live_gui_evidence=bad_hmi_evidence)
    assert ver_bad_hmi["status"] == "failed"
    assert ver_bad_hmi["verdict"] == "FAIL"
    assert ver_bad_hmi["reopen_ok"] is False



def test_all_imports_in_g12_and_g3_g7_g8_g9_g10_g11_smoke() -> None:
    """AST + runtime smoke test verifying every import in g12_estacion_bombeo_campaign.py and g3/g7/g8/g9/g10/g11."""
    import ast
    import importlib

    from scripts.g12_estacion_bombeo_campaign import (
        ID_EDIT_VARIABLES_AS_TEXT,
        ID_VIEW_PROGRAM_VARIABLES,
    )

    assert ID_EDIT_VARIABLES_AS_TEXT == 38141
    assert ID_VIEW_PROGRAM_VARIABLES == 38053

    # 1. Ensure g12_estacion_bombeo_campaign.py has zero nested imports hidden inside functions/methods
    g12_campaign_path = REPO_ROOT / "scripts" / "g12_estacion_bombeo_campaign.py"
    g12_tree = ast.parse(g12_campaign_path.read_text(encoding="utf-8"))
    for node in g12_tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for child in ast.walk(node):
                assert not isinstance(child, (ast.Import, ast.ImportFrom)), (
                    f"Nested import forbidden inside {node.name} at line {getattr(child, 'lineno', '?')} "
                    f"of g12_estacion_bombeo_campaign.py"
                )

    # 2. Walk AST of g12 + station_engine + all g3/g7/g8/g9/g10/g11 modules and verify every symbol exists at runtime
    target_files = [
        REPO_ROOT / "scripts" / "g12_estacion_bombeo_campaign.py",
        REPO_ROOT / "src" / "jev_cscape" / "estacion_bombeo_3b" / "station_engine.py",
        REPO_ROOT / "scripts" / "g3_edit_roundtrip.py",
        REPO_ROOT / "scripts" / "g7_acceptance.py",
        REPO_ROOT / "scripts" / "g7_campaign.py",
        REPO_ROOT / "scripts" / "g8_acceptance.py",
        REPO_ROOT / "scripts" / "g9_campaign.py",
        REPO_ROOT / "scripts" / "g10_campaign.py",
        REPO_ROOT / "scripts" / "g11_campaign.py",
        REPO_ROOT / "scripts" / "g11_acceptance.py",
        REPO_ROOT / "scripts" / "g12_release_campaign.py",
    ]
    missing: list[str] = []
    for path in target_files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    try:
                        importlib.import_module(alias.name)
                    except Exception as exc:
                        missing.append(f"{path.name}:{node.lineno} import {alias.name} -> {exc}")
            elif isinstance(node, ast.ImportFrom) and node.module and node.module != "__future__":
                try:
                    mod = importlib.import_module(node.module)
                    for alias in node.names:
                        if alias.name != "*" and not hasattr(mod, alias.name):
                            missing.append(
                                f"{path.name}:{node.lineno} from {node.module} import {alias.name} (MISSING)"
                            )
                except Exception as exc:
                    missing.append(f"{path.name}:{node.lineno} from {node.module} -> {exc}")

    assert missing == [], f"Unresolved imports detected: {missing}"


def test_all_call_sites_in_g12_campaign_and_station_engine_bind_signatures() -> None:
    """AST-extract every call site in g12_estacion_bombeo_campaign.py and station_engine.py and bind via inspect.signature."""
    import ast

    import jev_cscape.estacion_bombeo_3b.station_engine as eng_mod
    from jev_cscape.iec.st_parser import STParser
    from jev_cscape.security.guard import SecurityGuard
    from scripts.g3_edit_roundtrip import dismiss_popup_menu
    from scripts.g11_campaign import G11TypeSafeSystemOneClient
    import scripts.g12_estacion_bombeo_campaign as g12_mod

    # Negative self-check: prove inspect.signature(dismiss_popup_menu).bind rejects (main_hwnd=..., pid=...)
    with pytest.raises(TypeError):
        inspect.signature(dismiss_popup_menu).bind(main_hwnd=1, pid=2)

    method_owner_map = {
        "client": G11TypeSafeSystemOneClient,
        "guard": SecurityGuard,
        "parser": STParser,
        "ex": eng_mod.EstacionBombeo3BExecutor,
        "self.pid": eng_mod.PIDControllerBlock,
    }

    bind_errors: list[str] = []
    checked_calls = 0

    for mod_obj, path in [
        (g12_mod, REPO_ROOT / "scripts" / "g12_estacion_bombeo_campaign.py"),
        (eng_mod, REPO_ROOT / "src" / "jev_cscape" / "estacion_bombeo_3b" / "station_engine.py"),
    ]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            pos_args = [None] * len(node.args)
            kw_args = {kw.arg: None for kw in node.keywords if kw.arg is not None}

            if isinstance(node.func, ast.Name):
                fn_name = node.func.id
                fn_obj = getattr(mod_obj, fn_name, None)
                if callable(fn_obj) and getattr(fn_obj, "__module__", "").startswith(("scripts.", "jev_cscape.")):
                    checked_calls += 1
                    try:
                        sig = inspect.signature(fn_obj)
                        sig.bind(*pos_args, **kw_args)
                    except TypeError as exc:
                        bind_errors.append(
                            f"{path.name}:{node.lineno} {fn_name}{inspect.signature(fn_obj)} "
                            f"called with pos={len(pos_args)} kw={list(kw_args.keys())} -> {exc}"
                        )
            elif isinstance(node.func, ast.Attribute):
                owner_expr = ast.unparse(node.func.value)
                attr_name = node.func.attr
                owner_cls = method_owner_map.get(owner_expr)
                if owner_cls is not None and not (path.name == "g12_estacion_bombeo_campaign.py" and owner_expr == "parser"):
                    method_obj = getattr(owner_cls, attr_name, None)
                    if method_obj is None or not callable(method_obj):
                        bind_errors.append(
                            f"{path.name}:{node.lineno} {owner_expr}.{attr_name} does not exist on {owner_cls.__name__}"
                        )
                    else:
                        checked_calls += 1
                        try:
                            sig = inspect.signature(method_obj)
                            # Unbound class method has leading 'self' unless @staticmethod
                            if "self" in sig.parameters:
                                sig.bind(None, *pos_args, **kw_args)
                            else:
                                sig.bind(*pos_args, **kw_args)
                        except TypeError as exc:
                            bind_errors.append(
                                f"{path.name}:{node.lineno} {owner_expr}.{attr_name}{inspect.signature(method_obj)} "
                                f"called with pos={len(pos_args)} kw={list(kw_args.keys())} -> {exc}"
                            )

    assert checked_calls >= 120, f"Expected >= 120 verified call sites, got {checked_calls}"
    assert bind_errors == [], f"Call site signature bind errors: {bind_errors}"


def test_r20_pid_dialog_325_edit_12024_and_no_a10_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify R20 PID_IND populates all 7 CTagRegisterSelector Edit 12024 controls in DLG 325, keeps PID_IND tool mode on attempt 1 double-click, and sweeps stray I/O Point dialogs."""
    import ast
    import struct
    from jev_cscape.estacion_bombeo_3b.station_engine import (
        PHASE1_LADDER_26_RUNGS_GUI_SPEC,
        _parse_single_ladder_module_slice,
    )
    import scripts.g12_estacion_bombeo_campaign as g12_mod

    r20 = next(r for r in PHASE1_LADDER_26_RUNGS_GUI_SPEC if r["rung"] == "R20")
    assert r20["coil"]["type"] == "PID_IND"
    assert r20["coil"]["tag"] == "PID_BLK"
    assert "fallback_coil" not in r20["coil"]

    # 1. Verify _parse_single_ladder_module_slice handles real Cscape 10.2 CPid::Serialize (0x385033):
    #    opcode=14 + empty m_regAddress (\x00\x00) + <IIBB (col=1, row=22, flag24=0, m_bIsa=0) at s-10
    #    followed by all 7 operands: PID_BLK, PID_SP, PID_PV, ALW_OFF (Enable), ALW_OFF (Up), ALW_OFF (Down), PID_CV.
    vfd_contact = struct.pack("<BII", 0, 0, 22) + b"!\x07@VFD_HAB@"
    pid_cell_7ops = (
        b"\x0e\x00\x00"
        + struct.pack("<IIBB", 1, 22, 0, 0)
        + b"!\x07@PID_BLK@"
        + b"\x00\x00!\x06@PID_SP@"
        + b"\x00\x00!\x06@PID_PV@"
        + b"\x00\x00!\x07@ALW_OFF@"
        + b"\x00\x00!\x07@ALW_OFF@"
        + b"\x00\x00!\x07@ALW_OFF@"
        + b"\x00\x00!\x06@PID_CV@"
    )
    parsed = _parse_single_ladder_module_slice(vfd_contact + pid_cell_7ops, 2)
    assert parsed["distinct_rows_count"] == 1
    assert parsed["rows"] == [22]
    assert len(parsed["pid_blocks"]) == 1
    assert parsed["pid_blocks"][0]["tag"] == "PID_BLK"
    assert parsed["pid_blocks"][0]["operands"] == [
        "PID_BLK",
        "PID_SP",
        "PID_PV",
        "ALW_OFF",
        "ALW_OFF",
        "ALW_OFF",
        "PID_CV",
    ]

    # 2. Verify _assign_pid_in_dialog_325 populates all 7 CTagRegisterSelector Edit (12024) controls in DLG 325
    #    including idx 4..6 (Manual Control Enable/Up/Down -> ALW_OFF) and sends EN_UPDATE/EN_CHANGE to all 7.
    dlg_hwnd = 0x325000
    ok_btn = 0x325001
    io_point_hwnd = 0x108000
    io_cancel_btn = 0x108002
    edit_hwnds = [0x325200 + i for i in range(7)]
    parent_map = {0x325200 + i: 0x325100 + i for i in range(7)}
    rects = {0x325200 + i: (55, 11 + i * 18, 155, 23 + i * 18) for i in range(7)}
    settext_calls: dict[int, str] = {}
    en_change_notified: set[int] = set()
    dlg_visible = True
    io_point_visible = True

    monkeypatch.setattr(g12_mod.win32process, "GetWindowThreadProcessId", lambda h: (1, 9999))
    monkeypatch.setattr(g12_mod.win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(
        g12_mod.win32gui,
        "IsWindowVisible",
        lambda h: dlg_visible if h == dlg_hwnd else (io_point_visible if h == io_point_hwnd else True),
    )
    monkeypatch.setattr(
        g12_mod.win32gui,
        "GetClassName",
        lambda h: "Edit" if h in edit_hwnds else ("Button" if h in (ok_btn, io_cancel_btn) else "#32770"),
    )
    monkeypatch.setattr(
        g12_mod.win32gui,
        "GetWindowText",
        lambda h: "PID Edit" if h == dlg_hwnd else ("I/O Point" if h == io_point_hwnd else ""),
    )
    monkeypatch.setattr(g12_mod.win32gui, "GetWindowRect", lambda h: rects.get(h, (0, 0, 100, 20)))
    monkeypatch.setattr(g12_mod.win32gui, "GetParent", lambda h: parent_map.get(h, dlg_hwnd))

    def _fake_enum_windows(cb: object, extra: object) -> None:
        for wh in (dlg_hwnd, io_point_hwnd):
            if cb(wh, extra) is False:  # type: ignore[misc]
                break

    monkeypatch.setattr(g12_mod.win32gui, "EnumWindows", _fake_enum_windows)

    def _fake_enum_children(parent: int, cb: object, extra: object) -> None:
        for eh in reversed(edit_hwnds):
            cb(eh, extra)  # type: ignore[misc]

    monkeypatch.setattr(g12_mod.win32gui, "EnumChildWindows", _fake_enum_children)

    class _FakeUser32:
        def GetDlgCtrlID(self, h: int) -> int:
            return 12024 if h in edit_hwnds else (1 if h == ok_btn else (2 if h == io_cancel_btn else 0))

        def GetDlgItem(self, h: int, cid: int) -> int:
            if h == dlg_hwnd and cid == 1:
                return ok_btn
            if h == io_point_hwnd and cid == 2:
                return io_cancel_btn
            return 0

        def SendMessageW(self, h: int, msg: int, wparam: int, lparam: object) -> int:
            if msg == g12_mod.win32con.WM_SETTEXT:
                settext_calls[h] = str(lparam)
            elif msg == g12_mod.win32con.WM_COMMAND and ((int(wparam) >> 16) & 0xFFFF) == 0x0300:
                en_change_notified.add(int(lparam))  # type: ignore[arg-type]
            return 1

        def PostMessageW(self, h: int, msg: int, wparam: int, lparam: object) -> int:
            nonlocal dlg_visible, io_point_visible
            if h == ok_btn and msg == g12_mod.win32con.BM_CLICK:
                dlg_visible = False
            if h in (io_point_hwnd, io_cancel_btn) and msg in (
                g12_mod.win32con.BM_CLICK,
                g12_mod.win32con.WM_CLOSE,
                g12_mod.win32con.WM_COMMAND,
            ):
                io_point_visible = False
            return 1

    monkeypatch.setattr(g12_mod.ctypes.windll, "user32", _FakeUser32())
    ok = g12_mod._assign_pid_in_dialog_325(
        pid=9999,
        blk_tag="PID_BLK",
        sp_tag="PID_SP",
        pv_tag="PID_PV",
        cv_tag="PID_CV",
        timeout=1.0,
    )
    assert ok is True
    assert settext_calls[edit_hwnds[0]] == "PID_BLK"
    assert settext_calls[edit_hwnds[1]] == "PID_SP"
    assert settext_calls[edit_hwnds[2]] == "PID_PV"
    assert settext_calls[edit_hwnds[3]] == "PID_CV"
    assert settext_calls[edit_hwnds[4]] == "ALW_OFF"
    assert settext_calls[edit_hwnds[5]] == "ALW_OFF"
    assert settext_calls[edit_hwnds[6]] == "ALW_OFF"
    assert en_change_notified == set(edit_hwnds)

    # 3. Verify _close_stray_ladder_dialogs sweeps stray 'I/O Point' (Dialog 108) modals
    closed_n = g12_mod._close_stray_ladder_dialogs(pid=9999)
    assert closed_n >= 1
    assert io_point_visible is False

    # 4. Verify _place_rungs_on_active_ladder_canvas AST keeps PID_IND tool mode active on pid_attempt == 1 double-click
    src = inspect.getsource(g12_mod._place_rungs_on_active_ladder_canvas)
    tree = ast.parse(src)
    found_attempt1_branch = False
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and ast.unparse(node.test) == "pid_attempt == 1":
            found_attempt1_branch = True
            branch_src = ast.unparse(node.body)
            assert "PHASE1_ID_PID_IND" in branch_src
            assert "WM_LBUTTONDBLCLK" in branch_src
            assert "ID_SELECT_ELEMENTS" not in branch_src
    assert found_attempt1_branch is True


def test_real_st_blocks_38055_w5editst_14byte_cpid_and_compile_clean_honesty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify: (1) real 14-byte CPid header (<BIIIB) + 0-byte continuation operands parse as PID_IND, (2) 4 ST blocks use 38055 (W5EditST Module Type 11) + 37466 rename with valid declared tags, (3) compile_clean is True when Cscape compiles cleanly even if reopen fails, and (4) _read_tag_from_dialog_108_in_gui does not post duplicate VK_RETURN."""
    import struct
    from jev_cscape.estacion_bombeo_3b.station_engine import (
        ALARMS_12_GUI_TAGS_SPEC,
        AUX_BITS_GUI_TAGS_SPEC,
        PHASE2_ID_NEW_IEC_ST_BLOCK,
        PHASE2_ID_RENAME_MODULE,
        PHASE2_ST_LOGIC_BLOCKS_GUI_SPEC,
        ST_BLOCKS_SOURCE,
        TAGS_59_SPEC,
        _parse_single_ladder_module_slice,
        extract_cscape_st_block_body,
    )
    import scripts.g12_estacion_bombeo_campaign as g12_mod

    # 1. Verify exact 14-byte CPid binary header from live Cscape 10.2 save (opcode=14, col=1, row=31, flag=0xc0, m_bIsa=1)
    #    and 0-byte continuation operands (!\t@PID_BLK@!\x08@PID_SP@!\x08@PID_PV@!\t@ALW_OFF@!\t@ALW_OFF@!\t@ALW_OFF@!\x08@PID_CV@)
    real_r20_bytes = (
        struct.pack("<BII", 0, 0, 31)
        + b"!\t@VFD_HAB@\x00\x00"
        + b"\x0e\x01\x00\x00\x00\x1f\x00\x00\x00\xc0\x00\x00\x00\x01"
        + b"!\t@PID_BLK@!\x08@PID_SP@!\x08@PID_PV@!\t@ALW_OFF@!\t@ALW_OFF@!\t@ALW_OFF@!\x08@PID_CV@"
    )
    parsed_r20 = _parse_single_ladder_module_slice(real_r20_bytes, 2)
    assert parsed_r20["distinct_rows_count"] == 1
    assert parsed_r20["rows"] == [31]
    assert len(parsed_r20["pid_blocks"]) == 1
    assert parsed_r20["pid_blocks"][0]["type"] == "PID_IND"
    assert parsed_r20["pid_blocks"][0]["tag"] == "PID_BLK"
    assert parsed_r20["pid_blocks"][0]["operands"] == [
        "PID_BLK",
        "PID_SP",
        "PID_PV",
        "ALW_OFF",
        "ALW_OFF",
        "ALW_OFF",
        "PID_CV",
    ]

    # If artifacts/G12/estacion_bombeo_3b.csp exists on disk and has post-rung ladder elements saved,
    # verify all 26 spec rungs and PID_BLK are detected
    saved_csp = REPO_ROOT / "artifacts" / "G12" / "estacion_bombeo_3b.csp"
    if saved_csp.is_file():
        m3 = parse_cscape_main3_rungs_and_elements(saved_csp)
        assert m3["valid"] is True
        if m3["total_elements"] > 0:
            assert m3["main_26_rungs_verified"] is True
            assert m3["main_26_rungs_matched_count"] == 26
            assert m3["pid_loop_count"] >= 1

    # 2. Verify all 4 ST blocks are configured as real Module Type 11 W5EditST blocks (cmd 38055, rename 37466)
    #    and every identifier in their ST code is either an IEC keyword/conversion or a declared tag in the 82-tag set
    assert PHASE2_ID_NEW_IEC_ST_BLOCK == 38055
    assert PHASE2_ID_RENAME_MODULE == 37466
    declared_upper = (
        {t["name"].upper() for t in TAGS_59_SPEC}
        | {a["name"].upper() for a in ALARMS_12_GUI_TAGS_SPEC}
        | {x["name"].upper() for x in AUX_BITS_GUI_TAGS_SPEC}
    )
    iec_keywords = {
        "IF",
        "THEN",
        "ELSIF",
        "ELSE",
        "END_IF",
        "AND",
        "OR",
        "NOT",
        "TRUE",
        "FALSE",
        "INT_TO_REAL",
        "REAL_TO_INT",
    }
    import re

    for blk in PHASE2_ST_LOGIC_BLOCKS_GUI_SPEC:
        assert blk["module_type"] == 11
        assert blk["editor_class"] == "W5EditST"
        assert blk["cmd_id"] == 38055
        assert blk["rename_cmd_id"] == 37466
        body = blk["code"]
        assert body == extract_cscape_st_block_body(ST_BLOCKS_SOURCE[blk["name"]])
        assert "PROGRAM " not in body
        assert "END_PROGRAM" not in body
        no_comments = re.sub(r"\(\*.*?\*\)", " ", body, flags=re.DOTALL)
        tokens = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", no_comments))
        undeclared = {tok.upper() for tok in tokens} - declared_upper - iec_keywords
        assert undeclared == set(), f"Undeclared identifiers in {blk['name']}: {undeclared}"

    # 3. Verify compile_clean reflects real compile evidence even if reopen/ST count fails
    staged_csp = tmp_path / "estacion_bombeo_3b.csp"
    stage_clean_p1_base_for_live_cscape(staged_csp)
    data = bytearray(staged_csp.read_bytes())
    data[-16:] = b"CSCAPE_SAVE_10_2"
    staged_csp.write_bytes(bytes(data))

    partial_evidence = {
        "live_gui_executed": True,
        "live_pid": 14520,
        "reopen_pid": 18940,
        "reopen_gui_verified": False,
        "sha_changed_after_rungs": True,
        "gui_readback_station_tags": 59,
        "gui_readback_alarm_tags": 12,
        "gui_readback_total_tags": 105,
        "gui_readback_rungs": 26,
        "gui_readback_st_blocks": 0,
        "gui_readback_pid_loops": 1,
        "reopen_compile_clean": True,
        "reopen_compile_errors": 0,
        "reopen_compile_warnings": 0,
        "reopen_duplicate_coil_warnings": 0,
    }
    ver_partial = verify_estacion_bombeo_3b_csp(staged_csp, live_gui_evidence=partial_evidence)
    assert ver_partial["status"] == "failed"
    assert ver_partial["verdict"] == "FAIL"
    assert ver_partial["compile_clean"] is True
    assert ver_partial["reopen_ok"] is False

    # 4. Verify _read_tag_from_dialog_108_in_gui does not send VK_RETURN (which queued a second stray 'I/O Point' dialog)
    d108_src = inspect.getsource(g12_mod._read_tag_from_dialog_108_in_gui)
    assert "WM_LBUTTONDBLCLK" in d108_src
    assert "VK_RETURN" not in d108_src
    assert "_close_stray_ladder_dialogs" in d108_src


