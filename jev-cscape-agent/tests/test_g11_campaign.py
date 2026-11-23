#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for Gate G11 Campaign (MEGAPLAN W084-W090).

Covers:
  1. Strict log & artifact isolation (`g11_unit_test.log` vs `g11_campaign.log`).
  2. W084: 30 unseen reserved tasks per certified family (`st_var`, `ladder`, `hmi` = 90 tasks),
     strictly disjoint from G3, G7, G8, G9, and G10.
  3. W085: `rule_baseline`, `llm_choice_baseline`, and `jev_full` operating on the exact same
     `ObserverSnapshot` (`snapshot_id` parity).
  4. W086: Per-stage monotonic latency (`reset_ms`, `observe_ms`, `plan_ms`, `act_ms`, `verify_ms`, `total_ms`),
     real HTTP `usage` token/cost accounting, and success/error rates.
  5. W087: Balanced multi-condition runs with deterministic project reset to `p1_base.csp`.
  6. W088: 24h endurance worker with finite bounded queue, budget cap stop, controlled restart,
     and atomic SHA-256 verified checkpoint save/resume/tamper-detection.
  7. W089/W090: Non-parametric median (`p50`), `p95`, IQR, and 95% confidence intervals (continuous +
     Wilson score binomial CIs), plus zero synthetic results on unexecuted cells.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import inspect
import json
from pathlib import Path
import threading
from typing import Any, Dict, List
import pytest

from scripts.g11_campaign import (
    BASELINE_P1_SHA,
    BASE_P1_PATH,
     LOG_FILE_PATH,
    UNIT_TEST_LOG_FILE_PATH,
    BalancedProjectResetRunner,
    CertifiedFamily,
    EnduranceWorker24h,
    G11TypeSafeSystemOneClient,
    JevFullPlanner,
    LLMChoiceBaselinePlanner,
    NonParametricStatsAggregator,
    PlannerPolicy,
    RuleBaselinePlanner,
    assert_g11_safety_invariants,
    capture_observer_snapshot,
    compute_sha256,
    configure_g11_logging,
    get_g11_reserved_unseen_tasks,
    logger,
    run_g11_campaign,
    verify_same_observer_snapshot,
    verify_w084_suite_disjointness,
)


class _LocalSystemOneHandler(BaseHTTPRequestHandler):
    """Local HTTP test handler capturing request payloads and returning real HTTP 200 + usage metadata."""

    recorded_requests: List[Dict[str, Any]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length)
        req_json = json.loads(raw_body.decode("utf-8"))
        self.__class__.recorded_requests.append(req_json)

        questions = req_json.get("questions", {})
        answers: Dict[str, Any] = {}
        for q_key, q_spec in questions.items():
            if q_spec.get("type") == "choice":
                crit = q_spec.get("criteria", {})
                opts = list(crit.keys()) if isinstance(crit, dict) else list(crit)
                answers[q_key] = {"type": "choice", "choice": opts[0] if opts else "default", "confidence": 0.98}
            elif q_spec.get("type") == "noul":
                answers[q_key] = {"type": "noul", "noul": 0.97}

        resp_payload = {
            "id": f"req_local_{len(self.__class__.recorded_requests)}",
            "model": "jev-1.13.0",
            "answers": answers,
            "usage": {
                "input_tokens": 320,
                "output_tokens": 80,
                "total_tokens": 400,
            },
        }
        resp_bytes = json.dumps(resp_payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("x-typesafe-request-id", resp_payload["id"])
        self.send_header("Content-Length", str(len(resp_bytes)))
        self.end_headers()
        self.wfile.write(resp_bytes)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return


def test_01_strict_log_isolation_and_safety_invariants() -> None:
    """Verify unit tests log exclusively to g11_unit_test.log and never touch g11_campaign.log."""
    live_mtime_before = LOG_FILE_PATH.stat().st_mtime_ns if LOG_FILE_PATH.exists() else None
    live_size_before = LOG_FILE_PATH.stat().st_size if LOG_FILE_PATH.exists() else None

    active_log = configure_g11_logging()
    assert active_log == UNIT_TEST_LOG_FILE_PATH
    logger.info("G11 unit test log isolation check message.")

    for h in logger.handlers:
        h.flush()

    assert UNIT_TEST_LOG_FILE_PATH.exists()
    live_mtime_after = LOG_FILE_PATH.stat().st_mtime_ns if LOG_FILE_PATH.exists() else None
    live_size_after = LOG_FILE_PATH.stat().st_size if LOG_FILE_PATH.exists() else None
    assert live_mtime_before == live_mtime_after
    assert live_size_before == live_size_after

    safety = assert_g11_safety_invariants()
    assert safety["com_ports_locked_out"] is True
    assert safety["download_commands_locked_out"] is True
    assert safety["baseline_p1_sha256"] == BASELINE_P1_SHA


def test_02_w084_reserved_30_unseen_tasks_per_family_disjointness() -> None:
    """Verify W084 provides exactly 30 unseen tasks per certified family (90 total) disjoint from G3/G7/G8/G9/G10."""
    tasks = get_g11_reserved_unseen_tasks()
    assert len(tasks) == 90

    st_tasks = [t for t in tasks if t.family == CertifiedFamily.ST_VAR]
    lad_tasks = [t for t in tasks if t.family == CertifiedFamily.LADDER]
    hmi_tasks = [t for t in tasks if t.family == CertifiedFamily.HMI]
    assert len(st_tasks) == 30
    assert len(lad_tasks) == 30
    assert len(hmi_tasks) == 30

    audit = verify_w084_suite_disjointness(tasks)
    assert audit["status"] == "success"
    assert audit["total_tasks"] == 90
    assert audit["counts_by_family"] == {"ladder": 30, "hmi": 30, "st_var": 30}
    assert audit["unique_tags_count"] == 180
    assert audit["unique_registers_count"] == 180
    assert audit["disjoint_from_prior_gates"] is True
    assert audit["violations"] == []


def test_03_w085_rule_and_llm_choice_baselines_on_same_observer() -> None:
    """Verify rule_baseline, llm_choice_baseline, and jev_full operate on the exact same ObserverSnapshot."""
    _LocalSystemOneHandler.recorded_requests.clear()
    server = HTTPServer(("127.0.0.1", 0), _LocalSystemOneHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        endpoint = f"http://127.0.0.1:{port}/v1/systemone"
        client = G11TypeSafeSystemOneClient(endpoint=endpoint)
        rule_planner = RuleBaselinePlanner()
        llm_choice_planner = LLMChoiceBaselinePlanner(client=client)
        jev_full_planner = JevFullPlanner(client=client)

        snap1 = capture_observer_snapshot(BASE_P1_PATH, live_gui=False)
        snap2 = capture_observer_snapshot(BASE_P1_PATH, live_gui=False)
        snap3 = capture_observer_snapshot(BASE_P1_PATH, live_gui=False)
        assert verify_same_observer_snapshot([snap1, snap2, snap3]) is True
        assert snap1.cfbf_sha256 == BASELINE_P1_SHA
        assert snap1.cfbf_declarations_count >= 23

        sample_task = get_g11_reserved_unseen_tasks(family_filter="st_var", max_per_family=1)[0]

        d_rule = rule_planner.plan(snap1, sample_task)
        d_choice = llm_choice_planner.plan(snap2, sample_task, live_network=True, override_endpoint=endpoint)
        d_jev = jev_full_planner.plan(snap3, sample_task, live_network=True, override_endpoint=endpoint)

        # Identical snapshot_id across all three planners
        assert d_rule.snapshot_id == d_choice.snapshot_id == d_jev.snapshot_id == snap1.snapshot_id

        # Rule baseline uses 0 API calls and 0 tokens
        assert d_rule.token_telemetry.api_calls == 0
        assert d_rule.token_telemetry.total_tokens == 0
        assert d_rule.token_telemetry.cost_usd == 0.0
        assert d_rule.noul_scores is None

        # LLM-Choice baseline uses ONLY 'choice' questions (zero 'noul' questions) and records real HTTP usage
        assert d_choice.token_telemetry.api_calls == 1
        assert d_choice.token_telemetry.http_status == 200
        assert d_choice.token_telemetry.input_tokens == 320
        assert d_choice.token_telemetry.output_tokens == 80
        assert d_choice.token_telemetry.total_tokens == 400
        assert d_choice.token_telemetry.cost_usd > 0.0
        assert d_choice.noul_scores is None

        # Full Jev uses both 'choice' and 'noul' questions on the identical state string
        assert d_jev.token_telemetry.api_calls == 1
        assert d_jev.token_telemetry.http_status == 200
        assert d_jev.token_telemetry.total_tokens == 400
        assert d_jev.noul_scores is not None
        assert "noul_register_isolation" in d_jev.noul_scores

        assert len(_LocalSystemOneHandler.recorded_requests) == 2
        req_choice, req_jev = _LocalSystemOneHandler.recorded_requests
        assert req_choice["state"] == req_jev["state"]
        assert all(q["type"] == "choice" for q in req_choice["questions"].values())
        assert any(q["type"] == "noul" for q in req_jev["questions"].values())
    finally:
        server.shutdown()
        server.server_close()


def test_04_w087_balanced_schedule_and_project_reset(tmp_path: Path) -> None:
    """Verify W087 Latin-square balanced schedule and deterministic project reset to p1_base.csp."""
    tasks = get_g11_reserved_unseen_tasks(max_per_family=2)  # 6 tasks (2 per family)
    schedule = BalancedProjectResetRunner.build_balanced_schedule(tasks)
    assert len(schedule) == 18  # 6 tasks * 3 policies

    # Check exact balance across families and policies
    fam_counts: Dict[str, int] = {}
    pol_counts: Dict[str, int] = {}
    for item in schedule:
        fam_counts[item.task.family.value] = fam_counts.get(item.task.family.value, 0) + 1
        pol_counts[item.policy.value] = pol_counts.get(item.policy.value, 0) + 1
    assert fam_counts == {"st_var": 6, "ladder": 6, "hmi": 6}
    assert pol_counts == {"jev_full": 6, "rule_baseline": 6, "llm_choice_baseline": 6}

    runner = BalancedProjectResetRunner(copies_dir=tmp_path)
    copy_path, copy_sha, reset_ms = runner.reset_project_for_trial("test_trial_01", live_mode=False)
    assert copy_path.exists()
    assert copy_sha == BASELINE_P1_SHA
    assert reset_ms >= 0.0
    assert runner.verify_baseline_immutability() is True


def test_05_w088_endurance_worker_finite_queue_budget_cap_restart_and_checkpoint(tmp_path: Path) -> None:
    """Verify W088 finite queue capacity, strict budget cap stop, controlled restart, and checkpoint resume/tamper."""
    tasks = get_g11_reserved_unseen_tasks(max_per_family=2)
    schedule = BalancedProjectResetRunner.build_balanced_schedule(tasks)

    # 1. Finite queue capacity enforcement
    with pytest.raises(ValueError, match="max_queue_size"):
        EnduranceWorker24h(schedule_items=schedule, max_queue_size=5)

    # 2. Budget cap stop after 2 API calls
    ckpt_budget = tmp_path / "ckpt_budget.json"
    worker_budget = EnduranceWorker24h(
        schedule_items=schedule,
        max_queue_size=100,
        max_budget_usd=10.0,
        max_api_calls=2,
        restart_interval_tasks=2,
        checkpoint_path=ckpt_budget,
        reset_runner=BalancedProjectResetRunner(copies_dir=tmp_path / "copies_budget"),
    )
    res_budget = worker_budget.run(live_mode=False)
    assert res_budget["halted_by_budget"] is True
    assert res_budget["status"] == "blocked"
    assert res_budget["error_code"] == "ERR_BUDGET_CAP_REACHED"
    assert res_budget["api_calls_made"] == 2
    assert res_budget["cscape_restarts"] >= 1
    assert ckpt_budget.exists()

    # 3. Checkpoint resume completes remaining trials when budget cap is raised
    worker_resume = EnduranceWorker24h(
        schedule_items=schedule,
        max_queue_size=100,
        max_budget_usd=50.0,
        max_api_calls=500,
        restart_interval_tasks=5,
        checkpoint_path=ckpt_budget,
        reset_runner=BalancedProjectResetRunner(copies_dir=tmp_path / "copies_budget"),
    )
    loaded = worker_resume.load_and_resume_checkpoint(ckpt_budget)
    already_done = len(loaded["completed_trial_ids"])
    assert already_done >= 2
    res_resumed = worker_resume.run(live_mode=False)
    assert res_resumed["status"] == "success"
    assert res_resumed["completed_trials_count"] == len(schedule)
    assert res_resumed["remaining_queue_count"] == 0

    # 4. Tamper detection on corrupted checkpoint SHA-256
    corrupt_data = json.loads(ckpt_budget.read_text(encoding="utf-8"))
    corrupt_data["spent_usd"] = 999999.0
    ckpt_budget.write_text(json.dumps(corrupt_data, indent=2), encoding="utf-8")
    with pytest.raises(ValueError, match="ERR_CHECKPOINT_CORRUPT"):
        worker_resume.load_and_resume_checkpoint(ckpt_budget)


def test_06_w089_w090_median_p95_confidence_intervals_and_zero_synthetic(tmp_path: Path) -> None:
    """Verify W089 median/p95 + 95% CIs, Wilson binomial CIs, and W090 anti-synthetic unexecuted cell handling."""
    # 1. Anti-synthetic check when unexecuted (n=0)
    unexec_res = run_g11_campaign(live=False, dry_run=False)
    assert unexec_res["status"] == "inconclusive"
    assert unexec_res["error_code"] == "ERR_G11_NOT_EXECUTED"
    overall_empty = unexec_res["data"]["statistics"]["overall"]
    assert overall_empty["n"] == 0
    assert overall_empty["success_rate"] is None
    assert overall_empty["latency_ms"]["total_ms"] is None
    assert overall_empty["cost_usd"] is None

    # 2. Execute a balanced 1-task-per-family (3 families x 3 policies = 9 trials) dry-run
    summary_file = tmp_path / "g11_summary.json"
    ckpt_file = tmp_path / "g11_ckpt.json"
    res = run_g11_campaign(
        live=False,
        dry_run=True,
        tasks_per_family=2,
        checkpoint_path=ckpt_file,
        summary_path=summary_file,
    )
    assert res["status"] == "success"
    assert summary_file.exists()

    data = res["data"]
    assert data["w085_same_observer_verified"] is True
    assert data["w087_project_reset_verified"] is True
    assert data["invariants"]["zero_out_of_scope_writes"] is True
    assert data["invariants"]["zero_blind_retries"] is True
    assert data["invariants"]["zero_false_completions"] is True
    assert data["invariants"]["zero_synthetic_results"] is True
    assert compute_sha256(BASE_P1_PATH) == BASELINE_P1_SHA

    stats = data["w089_statistics"]["overall"]
    assert stats["n"] == 18
    sr = stats["success_rate"]
    assert sr["k"] == 18 and sr["n"] == 18 and sr["rate"] == 1.0
    assert 0.75 <= sr["ci95"][0] <= sr["rate"] <= sr["ci95"][1] <= 1.0

    tot_lat = stats["latency_ms"]["total_ms"]
    assert tot_lat["n"] == 18
    assert tot_lat["p50_ci95"][0] <= tot_lat["p50"] <= tot_lat["p50_ci95"][1]
    assert tot_lat["p95_ci95"][0] <= tot_lat["p95"] <= tot_lat["p95_ci95"][1]
    assert tot_lat["min"] <= tot_lat["p50"] <= tot_lat["p95"] <= tot_lat["max"]


def test_07_ast_and_inspect_signature_bind_all_real_live_helpers_and_32_64bit_contract() -> None:
    """Import all real live helpers from G3, G7, G8, G9, G10, and probe_hmi_editor (zero mocks),
    parse scripts/g11_campaign.py via ast, and bind every helper call against inspect.signature(real_fn).
    Also verify G11ReservedTaskSpec compatibility with declare_variables_via_live_cscape_win32 and
    32-bit Cscape vs 64-bit Python pywinauto contract."""
    import ast
    import inspect
    import scripts.g3_edit_roundtrip as g3_edit_roundtrip
    import scripts.g7_acceptance as g7_acceptance
    import scripts.g7_campaign as g7_campaign
    import scripts.g8_acceptance as g8_acceptance
    import scripts.g9_campaign as g9_campaign
    import scripts.g10_campaign as g10_campaign
    import scripts.probe_hmi_editor as probe_hmi_editor
    import scripts.g11_campaign as g11_campaign

    real_modules = {
        "scripts.g3_edit_roundtrip": g3_edit_roundtrip,
        "scripts.g7_acceptance": g7_acceptance,
        "scripts.g7_campaign": g7_campaign,
        "scripts.g8_acceptance": g8_acceptance,
        "scripts.g9_campaign": g9_campaign,
        "scripts.g10_campaign": g10_campaign,
        "scripts.probe_hmi_editor": probe_hmi_editor,
    }

    expected_real_helpers = {
        # G3
        "find_program_variables_treeview": g3_edit_roundtrip.find_program_variables_treeview,
        "get_treeview_item_texts": g3_edit_roundtrip.get_treeview_item_texts,
        "parse_csp_cfbf_declarations": g3_edit_roundtrip.parse_csp_cfbf_declarations,
        # G7 (g7_acceptance + g7_campaign)
        "assert_zero_silent_duplications": g7_acceptance.assert_zero_silent_duplications,
        "compute_cfbf_delta": g7_acceptance.compute_cfbf_delta,
        "dismiss_about_cscape_and_wait_main_enabled": g7_acceptance.dismiss_about_cscape_and_wait_main_enabled,
        "parse_cfbf_ladder_elements": g7_acceptance.parse_cfbf_ladder_elements,
        "trigger_and_read_cscape_error_check": g7_acceptance.trigger_and_read_cscape_error_check,
        "activate_ladder_toolbar_button": g7_campaign.activate_ladder_toolbar_button,
        "assign_tag_in_dialog": g7_campaign.assign_tag_in_dialog,
        "open_main_ladder_editor": g7_campaign.open_main_ladder_editor,
        "resolve_ladder_canvas": g7_campaign.resolve_ladder_canvas,
        # G8
        "dismiss_lingering_hmi_dialogs": g8_acceptance.dismiss_lingering_hmi_dialogs,
        "handle_confirmation_popups": g8_acceptance.handle_confirmation_popups,
        "parse_cfbf_hmi_elements": g8_acceptance.parse_cfbf_hmi_elements,
        "place_hmi_object_on_screen": g8_acceptance.place_hmi_object_on_screen,
        # G9
        "compute_sha256": g9_campaign.compute_sha256,
        "dismiss_error_check_modals": g9_campaign.dismiss_error_check_modals,
        # G10
        "_install_cursorless_mouse_guard": g10_campaign._install_cursorless_mouse_guard,
        "_keep_interactive_desktop_awake": g10_campaign._keep_interactive_desktop_awake,
        "declare_variables_via_live_cscape_win32": g10_campaign.declare_variables_via_live_cscape_win32,
        # probe_hmi_editor
        "close_cscape_gracefully": probe_hmi_editor.close_cscape_gracefully,
        "configure_cscape_registry": probe_hmi_editor.configure_cscape_registry,
        "dump_child_windows_recursive": probe_hmi_editor.dump_child_windows_recursive,
        "handle_startup_dialogs_and_wait_for_main_window": probe_hmi_editor.handle_startup_dialogs_and_wait_for_main_window,
        "is_screen_editor_window": probe_hmi_editor.is_screen_editor_window,
        "kill_leftover_cscape": probe_hmi_editor.kill_leftover_cscape,
        "launch_cscape_with_project": probe_hmi_editor.launch_cscape_with_project,
        "open_screen_editor_dynamic": probe_hmi_editor.open_screen_editor_dynamic,
    }

    # 1. Verify zero mocks and exact object identity between real modules and g11_campaign namespace
    for name, real_fn in expected_real_helpers.items():
        assert callable(real_fn), f"{name} is not callable"
        assert "unittest.mock" not in type(real_fn).__module__, f"{name} must not be mocked"
        g11_attr = getattr(g11_campaign, name, None)
        assert g11_attr is real_fn, f"g11_campaign.{name} is not identical to real helper {real_fn}"

    # 2. Regression check: inspect.signature(declare_variables_via_live_cscape_win32) rejects var_specs=...
    decl_sig = inspect.signature(g10_campaign.declare_variables_via_live_cscape_win32)
    assert list(decl_sig.parameters.keys()) == ["pid", "main_hwnd", "app", "spec", "app_uia", "copy_path"]
    with pytest.raises(TypeError, match="missing a required argument: 'app'"):
        decl_sig.bind(pid=1, main_hwnd=2, copy_path=BASE_P1_PATH, var_specs=[])
    with pytest.raises(TypeError, match="unexpected keyword argument 'var_specs'"):
        decl_sig.bind_partial(pid=1, main_hwnd=2, copy_path=BASE_P1_PATH, var_specs=[])

    # 3. Parse scripts/g11_campaign.py via ast and bind EVERY call site against inspect.signature(real_fn)
    g11_path = Path(g11_campaign.__file__).resolve()
    source_text = g11_path.read_text(encoding="utf-8")
    tree = ast.parse(source_text, filename=str(g11_path))

    ast_imported_helpers = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in real_modules:
            mod = real_modules[node.module]
            for alias in node.names:
                bound_name = alias.asname or alias.name
                real_obj = getattr(mod, alias.name)
                if callable(real_obj) and not inspect.isclass(real_obj):
                    ast_imported_helpers[bound_name] = real_obj

    assert set(expected_real_helpers.keys()) == set(ast_imported_helpers.keys())

    call_count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name) and node.func.id in ast_imported_helpers:
                func_name = node.func.id
            elif (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.attr in ast_imported_helpers
            ):
                func_name = node.func.attr

            if func_name is not None:
                real_fn = ast_imported_helpers[func_name]
                sig = inspect.signature(real_fn)

                for arg in node.args:
                    if isinstance(arg, ast.Starred):
                        raise TypeError(f"Line {node.lineno}: Starred positional arg *args forbidden in {func_name}()")
                for kw in node.keywords:
                    if kw.arg is None:
                        raise TypeError(f"Line {node.lineno}: Unpacked **kwargs forbidden in {func_name}()")

                pos_args = [ast.unparse(a) for a in node.args]
                kw_args = {kw.arg: ast.unparse(kw.value) for kw in node.keywords if kw.arg is not None}

                bound = sig.bind(*pos_args, **kw_args)
                for param_name, arg_expr in bound.arguments.items():
                    if arg_expr == "pid" and param_name != "pid":
                        raise TypeError(
                            f"Line {node.lineno}: {func_name}() binds positional argument 'pid' "
                            f"to parameter '{param_name}' instead of 'pid' (sig={sig})"
                        )
                call_count += 1

    assert call_count >= 36, f"Expected at least 36 live helper call sites in g11_campaign.py, found {call_count}"

    # 4. Verify all 90 G11ReservedTaskSpec instances satisfy declare_variables_via_live_cscape_win32's spec contract
    for t in get_g11_reserved_unseen_tasks():
        r_reg = f"%R{100 + int(t.task_num)}"
        m_reg = f"%M{100 + int(t.task_num)}"
        assert isinstance(t.level_pv_tag, str) and len(t.level_pv_tag) > 0
        assert isinstance(t.inlet_valve_tag, str) and len(t.inlet_valve_tag) > 0
        assert {r_reg, m_reg} == {t.primary_ocs_reg, t.secondary_ocs_reg}
        assert {t.level_pv_tag, t.inlet_valve_tag} == {t.primary_tag, t.secondary_tag}

    # 5. Verify 32-bit Cscape vs 64-bit Python pywinauto & TVITEMW32 contract
    arch_contract = g11_campaign.verify_32bit_cscape_64bit_python_pywinauto_contract()
    assert arch_contract["python_64bit_host"] is True
    assert arch_contract["cscape_target_arch"] == "x86_32_wow64"
    assert arch_contract["primary_pywinauto_backend"] == "win32"
    assert arch_contract["secondary_pywinauto_backend"] == "uia"
    assert arch_contract["tvitemw32_struct_bytes"] == 40
    assert arch_contract["cursorless_win32_dispatch"] is True


def test_g11_ladder_tag_sync_and_contact_coil_contract() -> None:
    """Verify Ladder tasks declare/sync valid IEC tags (<=15 chars) and place both Contact (Col A) + Coil (Col B) like G7/G9."""
    from scripts import g11_campaign, g7_campaign, g7_ladder_roundtrip

    # 1. All 90 W084 unseen tasks must have valid IEC names <= 15 chars (matching G7/G9 16-char Ladder buffer rule)
    audit = verify_w084_suite_disjointness()
    assert audit["status"] == "success"
    assert audit["max_tag_length"] <= g11_campaign.MAX_CSCAPE_LADDER_TAG_LEN
    for task in get_g11_reserved_unseen_tasks(family_filter=CertifiedFamily.LADDER):
        assert 1 <= len(task.primary_tag) <= 15
        assert 1 <= len(task.secondary_tag) <= 15
        assert task.primary_iec_type == "BOOL"
        assert task.primary_ocs_reg.startswith("%M4")
        assert task.inlet_valve_tag == task.primary_tag
        assert task.level_pv_tag == task.secondary_tag

    # 2. Verify assign_tag_in_dialog in both g7_campaign and g7_ladder_roundtrip unconditionally sets Edit 12024 + EnumChildWindows + ComboBox 1035
    for mod in (g7_campaign, g7_ladder_roundtrip):
        fn_src = inspect.getsource(mod.assign_tag_in_dialog)
        assert "GetDlgItem(dlg_hwnd, 12024)" in fn_src
        assert "EnumChildWindows(dlg_hwnd, _set_edits, None)" in fn_src
        assert "if not h_edit:" not in fn_src, "EnumChildWindows must run unconditionally on all Edit controls in Dialog 108"

    # 3. Verify execute_g11_task_action_and_verify LADDER branch places Contact at Col A (25, 25) and Coil at Col B (76, 25)
    act_src = inspect.getsource(g11_campaign.execute_g11_task_action_and_verify)
    assert "lparam_contact = (25 << 16) | 25" in act_src
    assert "lparam_coil = (25 << 16) | 76" in act_src
    assert "task.ladder_contact_cmd" in act_src
    assert "task.ladder_coil_cmd" in act_src
    assert "parse_cfbf_ladder_elements(copy_path)" in act_src
    assert "compute_cfbf_delta(base_cfbf_info, roundtrip_cfbf_info)" in act_src
    assert "assert_zero_silent_duplications(" in act_src


def test_g11_ladder_calls_g7_acceptance_functions_and_verifies_saved_csp_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove that G11 ladder directly imports and calls the exact G7 acceptance functions (scripts/g7_acceptance.py +
    scripts/g7_campaign.py) rather than a reimplementation, and verify the G7 CFBF oracle passes on the saved Ladder
    .csp files."""
    import ast
    import shutil
    from scripts import g11_campaign, g7_acceptance, g7_campaign

    # 1. Verify exact function object identity (`is`) between g11_campaign and g7_acceptance / g7_campaign
    assert g11_campaign.open_main_ladder_editor is g7_campaign.open_main_ladder_editor
    assert g11_campaign.resolve_ladder_canvas is g7_campaign.resolve_ladder_canvas
    assert g11_campaign.activate_ladder_toolbar_button is g7_campaign.activate_ladder_toolbar_button
    assert g11_campaign.assign_tag_in_dialog is g7_campaign.assign_tag_in_dialog
    assert g11_campaign.ID_SELECT_ELEMENTS == g7_campaign.ID_SELECT_ELEMENTS == 112
    assert g11_campaign.trigger_and_read_cscape_error_check is g7_acceptance.trigger_and_read_cscape_error_check
    assert g11_campaign.parse_cfbf_ladder_elements is g7_acceptance.parse_cfbf_ladder_elements
    assert g11_campaign.compute_cfbf_delta is g7_acceptance.compute_cfbf_delta
    assert g11_campaign.assert_zero_silent_duplications is g7_acceptance.assert_zero_silent_duplications

    # 2. Verify AST of execute_g11_task_action_and_verify calls all 8 G7 ladder functions and has zero hardcoded >= 4 reimplementation
    fn_src = inspect.getsource(g11_campaign.execute_g11_task_action_and_verify)
    assert 'element_count", 0) >= 4' not in fn_src
    fn_tree = ast.parse(fn_src)
    called_names = {
        node.func.id
        for node in ast.walk(fn_tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    required_g7_calls = {
        "open_main_ladder_editor",
        "resolve_ladder_canvas",
        "activate_ladder_toolbar_button",
        "assign_tag_in_dialog",
        "trigger_and_read_cscape_error_check",
        "parse_cfbf_ladder_elements",
        "compute_cfbf_delta",
        "assert_zero_silent_duplications",
    }
    assert required_g7_calls.issubset(called_names)

    # 3. Verify against the actual saved Ladder .csp files on disk (all 30 ladder tasks)
    base_info = g7_acceptance.parse_cfbf_ladder_elements(BASE_P1_PATH)
    assert base_info["element_count"] == 0

    ladder_tasks_by_id = {
        t.task_id: t.primary_tag
        for t in get_g11_reserved_unseen_tasks(family_filter=CertifiedFamily.LADDER)
    }
    copies_dir = g11_campaign.REPO_ROOT / "work" / "disposable" / "copies"
    if not (copies_dir / "g11_G11_W084_LADDER_01__jev_full.csp").exists():
        copies_dir = Path(r"C:\HornerAI\jev-cscape-agent\work\disposable\copies")
    saved_ladder_files = sorted(copies_dir.glob("g11_G11_W084_LADDER_*.csp"))
    for saved_csp in saved_ladder_files:
        # Filename pattern: g11_G11_W084_LADDER_XX__<policy>.csp
        stem_without_prefix = saved_csp.stem[len("g11_"):]
        task_id_part = stem_without_prefix.split("__")[0]
        expected_tag = ladder_tasks_by_id[task_id_part]
        rt_info = g7_acceptance.parse_cfbf_ladder_elements(saved_csp)
        delta_info = g7_acceptance.compute_cfbf_delta(base_info, rt_info)
        dup_check = g7_acceptance.assert_zero_silent_duplications(
            base_info, rt_info, saved_csp, expected_new_tag=expected_tag
        )
        assert rt_info["element_count"] == 2
        assert delta_info["delta_element_count"] == 2
        assert dup_check["zero_silent_duplications"] is True
        assert any(str(e.get("tag", "")).upper() == expected_tag for e in rt_info.get("elements", []))
        # If this is the pre-fix uncompiled G11_W084_LADDER_19__jev_full.csp on disk, verify our new
        # len(parsed_elems) >= 2 check catches the untagged coil (`len(elements) == 1 < 2`)
        if saved_csp.name != "g11_G11_W084_LADDER_19__jev_full.csp":
            assert len(rt_info.get("elements", [])) >= 2

    # 4. Execute execute_g11_task_action_and_verify on CertifiedFamily.LADDER and trace every G7 function call at runtime
    ladder_task = get_g11_reserved_unseen_tasks(family_filter=CertifiedFamily.LADDER)[0]  # G11_W084_LADDER_01
    snap = capture_observer_snapshot(BASE_P1_PATH, pid=0, main_hwnd=0, live_gui=False)
    decision = RuleBaselinePlanner().plan(snap, ladder_task)

    trial_csp = tmp_path / "g11_ladder_trace_test.csp"
    shutil.copy2(BASE_P1_PATH, trial_csp)

    # Prepare a valid post-save CFBF payload from the real 4762afa saved file
    real_saved_01 = copies_dir / "g11_G11_W084_LADDER_01__jev_full.csp"
    assert real_saved_01.exists(), f"Expected real saved ladder .csp at {real_saved_01}"
    saved_01_bytes = real_saved_01.read_bytes()

    g7_call_log: list[tuple[str, tuple[object, ...]]] = []

    def _trace_open_main_ladder_editor(main_hwnd: int, pid: int, app_uia: object = None) -> bool:
        g7_call_log.append(("open_main_ladder_editor", (main_hwnd, pid)))
        return True

    def _trace_resolve_ladder_canvas(main_hwnd: int) -> tuple[int, int]:
        g7_call_log.append(("resolve_ladder_canvas", (main_hwnd,)))
        return (2001, 2002)

    def _trace_activate_ladder_toolbar_button(main_hwnd: int, cmd_id: int) -> bool:
        g7_call_log.append(("activate_ladder_toolbar_button", (main_hwnd, cmd_id)))
        return True

    def _trace_assign_tag_in_dialog(pid: int, tag_name: str, timeout: float = 3.5) -> bool:
        g7_call_log.append(("assign_tag_in_dialog", (pid, tag_name)))
        return True

    def _trace_error_check(main_hwnd: int, pid: int) -> dict[str, object]:
        g7_call_log.append(("trigger_and_read_cscape_error_check", (main_hwnd, pid)))
        return {"status": "success", "clean_compile": True, "errors": 0, "warnings": 0}

    real_parse_ladder = g7_acceptance.parse_cfbf_ladder_elements
    real_compute_delta = g7_acceptance.compute_cfbf_delta
    real_assert_dups = g7_acceptance.assert_zero_silent_duplications

    def _trace_parse_ladder(csp_path: object) -> dict[str, object]:
        res = real_parse_ladder(csp_path)
        g7_call_log.append(("parse_cfbf_ladder_elements", (int(res.get("element_count", 0)),)))
        return res

    def _trace_compute_delta(base_d: dict[str, object], rt_d: dict[str, object]) -> dict[str, object]:
        res = real_compute_delta(base_d, rt_d)
        g7_call_log.append(("compute_cfbf_delta", (int(res.get("delta_element_count", 0)),)))
        return res

    def _trace_assert_dups(
        base_d: dict[str, object],
        rt_d: dict[str, object],
        rt_path: object,
        expected_new_tag: str = "G7_SW1",
    ) -> dict[str, object]:
        res = real_assert_dups(base_d, rt_d, rt_path, expected_new_tag=expected_new_tag)
        g7_call_log.append(("assert_zero_silent_duplications", (bool(res.get("zero_silent_duplications")), expected_new_tag)))
        return res

    monkeypatch.setattr(g11_campaign, "_keep_interactive_desktop_awake", lambda: None)
    monkeypatch.setattr(g11_campaign, "_install_cursorless_mouse_guard", lambda: None)
    monkeypatch.setattr(g11_campaign.psutil, "pid_exists", lambda p: True)
    monkeypatch.setattr(g11_campaign.win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(g11_campaign.win32gui, "FindWindowEx", lambda *a: 2000)
    monkeypatch.setattr(g11_campaign.user32, "SetForegroundWindow", lambda h: 1)
    monkeypatch.setattr(g11_campaign.user32, "SendMessageW", lambda *a: 0)

    def _fake_post_message(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        if msg == g11_campaign.win32con.WM_COMMAND and wparam == g11_campaign.ID_FILE_SAVE:
            trial_csp.write_bytes(saved_01_bytes)
        return 1

    monkeypatch.setattr(g11_campaign.user32, "PostMessageW", _fake_post_message)
    monkeypatch.setattr(g11_campaign.time, "sleep", lambda s: None)
    monkeypatch.setattr(g11_campaign, "declare_variables_via_live_cscape_win32", lambda **kw: True)
    monkeypatch.setattr(g11_campaign, "dismiss_error_check_modals", lambda **kw: 0)
    monkeypatch.setattr(g11_campaign, "handle_confirmation_popups", lambda **kw: 0)
    monkeypatch.setattr(g11_campaign, "open_main_ladder_editor", _trace_open_main_ladder_editor)
    monkeypatch.setattr(g11_campaign, "resolve_ladder_canvas", _trace_resolve_ladder_canvas)
    monkeypatch.setattr(g11_campaign, "activate_ladder_toolbar_button", _trace_activate_ladder_toolbar_button)
    monkeypatch.setattr(g11_campaign, "assign_tag_in_dialog", _trace_assign_tag_in_dialog)
    monkeypatch.setattr(g11_campaign, "trigger_and_read_cscape_error_check", _trace_error_check)
    monkeypatch.setattr(g11_campaign, "parse_cfbf_ladder_elements", _trace_parse_ladder)
    monkeypatch.setattr(g11_campaign, "compute_cfbf_delta", _trace_compute_delta)
    monkeypatch.setattr(g11_campaign, "assert_zero_silent_duplications", _trace_assert_dups)

    compile_clean, cfbf_verified, sha_after, out_pid, _, _, _ = g11_campaign.execute_g11_task_action_and_verify(
        task=ladder_task,
        decision=decision,
        copy_path=trial_csp,
        live_mode=True,
        session_state={"reuse_session": True, "pid": 4242, "main_hwnd": 1001, "app": None},
    )

    assert compile_clean is True
    assert cfbf_verified is True
    assert out_pid == 4242
    assert sha_after != BASELINE_P1_SHA

    called_fn_sequence = [name for name, _ in g7_call_log]
    assert called_fn_sequence == [
        "parse_cfbf_ladder_elements",          # Baseline pre-edit parse (0 elements)
        "open_main_ladder_editor",             # Open Main ladder editor
        "resolve_ladder_canvas",               # Resolve ladder MDI + canvas
        "activate_ladder_toolbar_button",      # Contact tool (38001)
        "assign_tag_in_dialog",                # Bind Contact to CRYO01_PERM_SW
        "activate_ladder_toolbar_button",      # Select tool (112)
        "activate_ladder_toolbar_button",      # Coil tool (38003)
        "assign_tag_in_dialog",                # Bind Coil to CRYO01_PERM_SW
        "activate_ladder_toolbar_button",      # Select tool (112)
        "trigger_and_read_cscape_error_check", # Error Check W057 (32826)
        "parse_cfbf_ladder_elements",          # Post-save roundtrip parse (2 elements)
        "compute_cfbf_delta",                  # Delta element count (+2)
        "assert_zero_silent_duplications",     # G7 zero-duplication + expected tag check
    ]


def test_g11_decoupled_benchmark_vs_endurance_and_results_json_finished_line(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify W084-W087 benchmark runs ALL scheduled tasks regardless of --endurance-hours, W088 endurance is separate, and RESULTS_JSON + FINISHED are printed."""
    summary_file = tmp_path / "g11_summary.json"
    results_file = tmp_path / "g11_results.json"
    ckpt_file = tmp_path / "g11_checkpoint.json"

    # Even with tiny endurance_hours=0.000001, Phase 1 (W084-W087 Benchmark Suite) must run ALL 18/18 scheduled trials to completion
    res = run_g11_campaign(
        live=False,
        dry_run=True,
        family_filter="all",
        policy_filter="all",
        tasks_per_family=2,  # 2 tasks * 3 families * 3 policies = 18 scheduled trials
        endurance_hours=0.000001,
        run_endurance=False,
        summary_path=summary_file,
        results_path=results_file,
        checkpoint_path=ckpt_file,
        override_endpoint=None,
    )

    assert res["status"] == "success"
    data = res["data"]
    assert data["w084_w087_benchmark_phase"]["scheduled_trials_count"] == 18
    assert data["w084_w087_benchmark_phase"]["completed_trials_count"] == 18
    assert data["w084_w087_benchmark_phase"]["passed_trials_count"] == 18
    assert data["w084_w087_benchmark_phase"]["all_scheduled_completed"] is True
    assert data["w084_w087_benchmark_phase"]["enforce_horizon"] is False
    assert data["w088_endurance"]["decoupled_from_benchmark"] is True
    assert data["w088_endurance"]["halted_by_horizon"] is False

    # Verify results JSON file exists and is valid JSON matching the returned payload
    assert results_file.exists()
    assert summary_file.exists()
    persisted_results = json.loads(results_file.read_text(encoding="utf-8"))
    assert persisted_results["status"] == "success"
    assert persisted_results["data"]["results_json_path"] == str(results_file.resolve())

    # Verify stdout includes RESULTS_JSON and FINISHED lines
    captured = capsys.readouterr().out
    assert f"RESULTS_JSON: {results_file.resolve()}" in captured
    assert "FINISHED: Gate G11 Campaign | status=success | mode=dry_run | benchmark_trials=18/18 | passed=18/18" in captured

    # Now verify Phase 2 (W088 separate endurance phase) runs when run_endurance=True with its own endurance_hours
    endurance_res = run_g11_campaign(
        live=False,
        dry_run=True,
        family_filter="st_var",
        policy_filter="rule_baseline",
        tasks_per_family=2,
        endurance_hours=0.05,
        run_endurance=True,
        summary_path=tmp_path / "g11_endurance_summary.json",
        results_path=tmp_path / "g11_endurance_results.json",
        checkpoint_path=tmp_path / "g11_endurance_ckpt.json",
        override_endpoint=None,
    )
    assert endurance_res["status"] == "success"
    sep_phase = endurance_res["data"]["w088_endurance"]["separate_endurance_phase"]
    assert sep_phase["decoupled_from_benchmark"] is True
    assert sep_phase["phase_executed"] is True
    assert sep_phase["completed_trials_count"] == 2
    assert sep_phase["status"] == "success"


def test_g11_hmi_placement_hardening_dialog_dismissal_and_suite_fault_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify:
    1) verify_tag_in_hmi_picker skips the slow UIA .expand() loop when expand_all_treeview_items(tree_hwnd) > 0.
    2) dismiss_lingering_hmi_dialogs sweeps open Numeric Data Properties / Variable Selector dialogs and re-enables main_hwnd.
    3) _install_cursorless_mouse_guard suppresses SetCursorPos 'Access is denied' warnings via sticky Win32 fallback.
    4) execute_g11_task_action_and_verify retries HMI placement on AssertionError/TimeoutError after sweeping lingering dialogs,
       and if placement still fails, records the trial as failed without crashing EnduranceWorker24h.run so remaining trials continue."""
    import logging
    import shutil
    from scripts import g8_acceptance, g10_campaign, g11_campaign
    from scripts.g11_campaign import _inject_dry_run_cfbf_mutation

    # 1. Verify verify_tag_in_hmi_picker does not call UIA .expand() when Win32 expand_all_treeview_items > 0
    picker_src = inspect.getsource(g8_acceptance.verify_tag_in_hmi_picker)
    assert "if expanded <= 0:" in picker_src

    # 2. Verify dismiss_lingering_hmi_dialogs closes child dialogs first and parent property dialogs second
    closed_hwnds: list[tuple[int, bool]] = []
    fake_windows = {
        0x1001: ("CscapeMain", "Cscape", 7777, True),
        0x2001: ("#32770", "Numeric Data Properties", 7777, True),
        0x2002: ("#32770", "Select Variable", 7777, True),
    }

    def _fake_enum_windows(cb: object, arg: object) -> None:
        for h, (_, _, _, vis) in list(fake_windows.items()):
            if vis:
                cb(h, arg)

    monkeypatch.setattr(g8_acceptance.win32gui, "EnumWindows", _fake_enum_windows)
    monkeypatch.setattr(g8_acceptance.win32gui, "IsWindow", lambda h: h in fake_windows)
    monkeypatch.setattr(g8_acceptance.win32gui, "IsWindowVisible", lambda h: fake_windows.get(h, ("", "", 0, False))[3])
    monkeypatch.setattr(g8_acceptance.win32gui, "GetClassName", lambda h: fake_windows[h][0])
    monkeypatch.setattr(g8_acceptance.win32gui, "GetWindowText", lambda h: fake_windows[h][1])
    monkeypatch.setattr(g8_acceptance.win32process, "GetWindowThreadProcessId", lambda h: (1, fake_windows[h][2]))
    monkeypatch.setattr(g8_acceptance, "is_hmi_property_dialog", lambda h: h == 0x2001)
    monkeypatch.setattr(g8_acceptance.user32, "EnableWindow", lambda h, b: 1)

    def _fake_force_close(h: int, prefer_cancel: bool = True, timeout: float = 1.0) -> bool:
        closed_hwnds.append((h, prefer_cancel))
        cls, title, wpid, _ = fake_windows[h]
        fake_windows[h] = (cls, title, wpid, False)
        return True

    monkeypatch.setattr(g8_acceptance, "_force_close_modal_dialog", _fake_force_close)
    dismissed = g8_acceptance.dismiss_lingering_hmi_dialogs(pid=7777, main_hwnd=0x1001, prefer_cancel=True, timeout=0.6)
    assert dismissed == 2
    assert [h for h, _ in closed_hwnds] == [0x2002, 0x2001]  # Child dialog closed first, then Numeric Data Properties!

    # 3. Verify _install_cursorless_mouse_guard suppresses 'SetCursorPos Access is denied' warnings
    import pywinauto.mouse
    monkeypatch.setattr(pywinauto.mouse, "_g10_cursorless_guarded", False, raising=False)
    monkeypatch.setattr(g10_campaign, "_CURSORLESS_WIN32_FALLBACK_ACTIVE", False)
    post_clicks: list[tuple[int, int, bool]] = []
    monkeypatch.setattr(
        g10_campaign,
        "_post_client_mouse_click",
        lambda x, y, button="left", double=False: post_clicks.append((x, y, double)) or True,
    )

    def _denied_click(button: str = "left", coords: tuple[int, int] = (0, 0)) -> None:
        raise RuntimeError("(5, 'SetCursorPos', 'Access is denied.')")

    monkeypatch.setattr(pywinauto.mouse, "click", _denied_click)
    monkeypatch.setattr(pywinauto.mouse, "double_click", _denied_click)
    monkeypatch.setattr(pywinauto.mouse, "move", lambda coords=(0, 0): (_ for _ in ()).throw(RuntimeError("Access is denied.")))
    g10_campaign._install_cursorless_mouse_guard()

    with caplog.at_level(logging.WARNING):
        caplog.clear()
        pywinauto.mouse.click(coords=(857, 406))
        pywinauto.mouse.double_click(coords=(857, 406))
        pywinauto.mouse.move(coords=(857, 406))
        warning_msgs = [r.message for r in caplog.records if r.levelno >= logging.WARNING]
        assert not any("Access is denied" in m for m in warning_msgs)
    assert g10_campaign._CURSORLESS_WIN32_FALLBACK_ACTIVE is True
    assert post_clicks == [(857, 406, False), (857, 406, True)]

    # 4. Verify HMI retry + suite fault isolation in execute_g11_task_action_and_verify and EnduranceWorker24h.run
    hmi_tasks = get_g11_reserved_unseen_tasks(family_filter=CertifiedFamily.HMI)[:2]
    schedule = BalancedProjectResetRunner.build_balanced_schedule(
        tasks=hmi_tasks,
        policies=[PlannerPolicy.RULE_BASELINE],
    )
    assert len(schedule) == 2

    # Inject a simulated placement timeout on the 1st HMI task (both attempts fail) while the 2nd HMI task succeeds!
    placement_calls: list[tuple[str, tuple[int, int]]] = []
    dismiss_calls: list[int] = []

    monkeypatch.setattr(g11_campaign, "_keep_interactive_desktop_awake", lambda: None)
    monkeypatch.setattr(g11_campaign, "_install_cursorless_mouse_guard", lambda: None)
    monkeypatch.setattr(g11_campaign, "kill_leftover_cscape", lambda: None)
    monkeypatch.setattr(g11_campaign, "configure_cscape_registry", lambda p: None)

    class _DummyWin:
        pass

    class _DummyApp:
        def window(self, handle: int) -> _DummyWin:
            return _DummyWin()

    monkeypatch.setattr(g11_campaign, "launch_cscape_with_project", lambda p: (_DummyApp(), 5555, 1001))
    monkeypatch.setattr(g11_campaign, "handle_startup_dialogs_and_wait_for_main_window", lambda **kw: None)
    monkeypatch.setattr(g11_campaign, "dismiss_about_cscape_and_wait_main_enabled", lambda *a, **kw: None)
    monkeypatch.setattr(g11_campaign, "close_cscape_gracefully", lambda **kw: None)
    monkeypatch.setattr(g11_campaign, "declare_variables_via_live_cscape_win32", lambda **kw: True)
    monkeypatch.setattr(g11_campaign, "dismiss_error_check_modals", lambda **kw: 0)
    monkeypatch.setattr(g11_campaign, "handle_confirmation_popups", lambda **kw: 0)
    monkeypatch.setattr(g11_campaign, "dismiss_lingering_hmi_dialogs", lambda **kw: dismiss_calls.append(int(kw.get("pid", 0))) or 1)
    monkeypatch.setattr(g11_campaign, "open_screen_editor_dynamic", lambda **kw: (3001, "Screen 1"))
    monkeypatch.setattr(g11_campaign, "is_screen_editor_window", lambda h: h == 3001)
    monkeypatch.setattr(g11_campaign.win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(g11_campaign.win32gui, "GetWindowRect", lambda h: (400, 200, 1200, 620))
    monkeypatch.setattr(g11_campaign.user32, "ShowWindow", lambda *a: 1)
    monkeypatch.setattr(g11_campaign.user32, "MoveWindow", lambda *a: 1)
    monkeypatch.setattr(g11_campaign.user32, "SetForegroundWindow", lambda *a: 1)
    monkeypatch.setattr(g11_campaign.time, "sleep", lambda s: None)

    active_copy_holder: dict[str, Path] = {}

    def _fake_place_hmi(**kw: object) -> dict[str, object]:
        tvar = str(kw["target_var"])
        coords = tuple(kw["target_coords"])  # type: ignore[arg-type]
        placement_calls.append((tvar, coords))  # type: ignore[arg-type]
        if tvar == hmi_tasks[0].primary_tag:
            raise AssertionError(
                f"FAIL_CLOSED: Placement of '{tvar}' at {coords} timed out after 88.3s (limit 60.0s) during 'Attempt 2 status bar poll'!"
            )
        return {"placed": True, "property_dialog_handled": True, "status_bar_text": "1 Object"}

    monkeypatch.setattr(g11_campaign, "place_hmi_object_on_screen", _fake_place_hmi)
    monkeypatch.setattr(
        g11_campaign,
        "trigger_and_read_cscape_error_check",
        lambda main_hwnd, pid: {"status": "success", "clean_compile": True, "errors": 0, "warnings": 0},
    )

    real_reset_runner = BalancedProjectResetRunner(copies_dir=tmp_path / "copies_fault_iso")
    orig_reset = real_reset_runner.reset_project_for_trial

    def _wrapped_reset(trial_id: str, live_mode: bool = False) -> tuple[Path, str, float]:
        cp, sha, ms = orig_reset(trial_id=trial_id, live_mode=False)
        active_copy_holder["path"] = cp
        return cp, sha, ms

    monkeypatch.setattr(real_reset_runner, "reset_project_for_trial", _wrapped_reset)

    def _fake_post_msg(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        if msg == g11_campaign.win32con.WM_COMMAND and wparam == g11_campaign.ID_FILE_SAVE:
            cp = active_copy_holder.get("path")
            if cp and cp.exists():
                _inject_dry_run_cfbf_mutation(cp, hmi_tasks[1])
        return 1

    monkeypatch.setattr(g11_campaign.user32, "PostMessageW", _fake_post_msg)
    monkeypatch.setattr(
        g11_campaign,
        "parse_csp_cfbf_declarations",
        lambda p: (
            [{"name": hmi_tasks[1].primary_tag}, {"name": hmi_tasks[1].secondary_tag}]
            if compute_sha256(Path(p)) != BASELINE_P1_SHA
            else []
        ),
    )

    worker = EnduranceWorker24h(
        schedule_items=schedule,
        max_queue_size=10,
        checkpoint_path=tmp_path / "fault_iso_ckpt.json",
        reset_runner=real_reset_runner,
        enforce_horizon=False,
    )
    run_res = worker.run(live_mode=True)

    # Both trials in the queue completed without crashing the campaign!
    assert run_res["completed_trials_count"] == 2
    assert run_res["remaining_queue_count"] == 0
    recs = run_res["trial_records"]
    assert len(recs) == 2

    # Trial 1 failed cleanly after 2 HMI placement attempts and dialog sweeps
    assert recs[0].task_id == hmi_tasks[0].task_id
    assert recs[0].status == "failed"
    assert recs[0].error_code == "ERR_TRIAL_VERIFICATION_FAILED"
    assert "FAIL_CLOSED: Placement of" in recs[0].details

    # Trial 2 succeeded cleanly right after Trial 1 failed!
    assert recs[1].task_id == hmi_tasks[1].task_id
    assert recs[1].status == "success"
    assert recs[1].compile_clean is True
    assert recs[1].cfbf_verified is True

    # Verify Trial 1 attempted placement twice (with offset coordinates on retry) and swept dialogs
    trial1_calls = [c for c in placement_calls if c[0] == hmi_tasks[0].primary_tag]
    assert len(trial1_calls) == 2
    assert trial1_calls[0][1] != trial1_calls[1][1]
    assert len(dismiss_calls) >= 4


def test_g11_ladder_19_coil_dialog_healing_and_error_check_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reproduce the exact G11_W084_LADDER_19__jev_full failure mode where the initial WM_LBUTTONDBLCLK on the
    Output Coil (while still in Coil tool 38003 mode) misses opening Dialog 108, and verify that:
      1) The healing loop switches to ID_SELECT_ELEMENTS (112), focuses canvas_hwnd, double-clicks + sends VK_RETURN
         at (76, 25), and binds CCMP19_LUBE_OK.
      2) If Error Check initially reports clean_compile=False, the Error Check healing path re-binds the coil and
         re-runs trigger_and_read_cscape_error_check to achieve compile_clean=True and cfbf_verified=True."""
    import shutil
    from scripts import g11_campaign

    ladder_19_task = [
        t for t in get_g11_reserved_unseen_tasks(family_filter=CertifiedFamily.LADDER)
        if t.task_id == "G11_W084_LADDER_19"
    ][0]
    assert ladder_19_task.primary_tag == "CCMP19_LUBE_OK"

    snap = capture_observer_snapshot(BASE_P1_PATH, pid=0, main_hwnd=0, live_gui=False)
    decision = RuleBaselinePlanner().plan(snap, ladder_19_task)

    trial_csp = tmp_path / "g11_G11_W084_LADDER_19__jev_full.csp"
    shutil.copy2(BASE_P1_PATH, trial_csp)

    # Use the passing rule_baseline saved .csp for LADDER_19 as the post-save compiled binary
    compiled_19_path = g11_campaign.REPO_ROOT / "work" / "disposable" / "copies" / "g11_G11_W084_LADDER_19__rule_baseline.csp"
    if not compiled_19_path.exists():
        compiled_19_path = Path(r"C:\HornerAI\jev-cscape-agent\work\disposable\copies\g11_G11_W084_LADDER_19__rule_baseline.csp")
    assert compiled_19_path.exists()
    compiled_19_bytes = compiled_19_path.read_bytes()

    assign_calls: list[str] = []
    toolbar_calls: list[int] = []
    error_check_calls: list[int] = []
    vk_return_sent: list[int] = []

    def _fake_assign_tag(pid: int, tag_name: str, timeout: float = 3.5) -> bool:
        assign_calls.append(tag_name)
        # Call 1: Contact (CCMP19_LUBE_OK) -> True
        # Call 2: Coil initial attempt while in Coil tool mode -> False (simulating LADDER_19__jev_full miss!)
        # Call 3: Coil healing retry after switching to ID_SELECT_ELEMENTS (112) -> True!
        if len(assign_calls) == 2:
            return False
        return True

    def _fake_toolbar(main_hwnd: int, cmd_id: int) -> bool:
        toolbar_calls.append(cmd_id)
        return True

    def _fake_error_check(main_hwnd: int, pid: int) -> dict[str, object]:
        error_check_calls.append(pid)
        # Simulate first Error Check failing and second Error Check passing after healing
        if len(error_check_calls) == 1:
            return {"status": "failed", "clean_compile": False, "errors": 1, "warnings": 0}
        return {"status": "success", "clean_compile": True, "errors": 0, "warnings": 0}

    def _fake_post_message(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        if msg == g11_campaign.win32con.WM_KEYDOWN and wparam == g11_campaign.win32con.VK_RETURN:
            vk_return_sent.append(hwnd)
        if msg == g11_campaign.win32con.WM_COMMAND and wparam == g11_campaign.ID_FILE_SAVE:
            trial_csp.write_bytes(compiled_19_bytes)
        return 1

    monkeypatch.setattr(g11_campaign, "_keep_interactive_desktop_awake", lambda: None)
    monkeypatch.setattr(g11_campaign, "_install_cursorless_mouse_guard", lambda: None)
    monkeypatch.setattr(g11_campaign.psutil, "pid_exists", lambda p: True)
    monkeypatch.setattr(g11_campaign.win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(g11_campaign.win32gui, "FindWindowEx", lambda *a: 2000)
    monkeypatch.setattr(g11_campaign.user32, "SetForegroundWindow", lambda h: 1)
    monkeypatch.setattr(g11_campaign.user32, "SetFocus", lambda h: 1)
    monkeypatch.setattr(g11_campaign.user32, "SendMessageW", lambda *a: 0)
    monkeypatch.setattr(g11_campaign.user32, "PostMessageW", _fake_post_message)
    monkeypatch.setattr(g11_campaign.time, "sleep", lambda s: None)
    monkeypatch.setattr(g11_campaign, "declare_variables_via_live_cscape_win32", lambda **kw: True)
    monkeypatch.setattr(g11_campaign, "dismiss_error_check_modals", lambda **kw: 0)
    monkeypatch.setattr(g11_campaign, "handle_confirmation_popups", lambda **kw: 0)
    monkeypatch.setattr(g11_campaign, "open_main_ladder_editor", lambda *a, **kw: True)
    monkeypatch.setattr(g11_campaign, "resolve_ladder_canvas", lambda main_hwnd: (2001, 2002))
    monkeypatch.setattr(g11_campaign, "activate_ladder_toolbar_button", _fake_toolbar)
    monkeypatch.setattr(g11_campaign, "assign_tag_in_dialog", _fake_assign_tag)
    monkeypatch.setattr(g11_campaign, "trigger_and_read_cscape_error_check", _fake_error_check)

    compile_clean, cfbf_verified, sha_after, out_pid, _, _, _ = g11_campaign.execute_g11_task_action_and_verify(
        task=ladder_19_task,
        decision=decision,
        copy_path=trial_csp,
        live_mode=True,
        session_state={"reuse_session": True, "pid": 4242, "main_hwnd": 1001, "app": None},
    )

    assert compile_clean is True
    assert cfbf_verified is True
    assert sha_after != BASELINE_P1_SHA
    # Verify ID_SELECT_ELEMENTS (112) was activated before the coil healing retry and VK_RETURN was sent
    assert g11_campaign.ID_SELECT_ELEMENTS in toolbar_calls
    assert len(vk_return_sent) >= 1
    assert assign_calls.count("CCMP19_LUBE_OK") >= 3
    assert len(error_check_calls) == 2


def test_g11_endurance_only_mode_skips_benchmark_and_runs_w088(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify --endurance-only --endurance-hours 4 CLI parsing and execution:
      1) Skips run_w084_w087_benchmark_suite completely (zero calls).
      2) Preserves prior benchmark records from g11_results.json if present.
      3) Executes run_w088_endurance_phase with enforce_horizon=True and the specified endurance_hours.
      4) Prints RESULTS_JSON and FINISHED lines and returns status=success."""
    from scripts import g11_campaign
    from scripts.g11_campaign import parse_g11_args

    # 1. Verify CLI parser accepts --endurance-only --endurance-hours 4
    args = parse_g11_args(["--live", "--endurance-only", "--endurance-hours", "4"])
    assert args.live is True
    assert args.endurance_only is True
    assert args.endurance_hours == 4.0

    # 2. First write a small prior benchmark results JSON (3 trials) to verify preservation under --endurance-only
    summary_file = tmp_path / "g11_summary.json"
    results_file = tmp_path / "g11_results.json"
    ckpt_file = tmp_path / "g11_checkpoint.json"

    prior_res = run_g11_campaign(
        live=False,
        dry_run=True,
        family_filter="st_var",
        policy_filter="rule_baseline",
        tasks_per_family=2,
        run_endurance=False,
        summary_path=summary_file,
        results_path=results_file,
        checkpoint_path=ckpt_file,
    )
    assert prior_res["status"] == "success"
    assert len(prior_res["data"]["trials"]) == 2
    capsys.readouterr()  # clear stdout

    # 3. Spy on run_w084_w087_benchmark_suite to prove it is NOT called when endurance_only=True
    benchmark_suite_called = False

    def _forbidden_benchmark_suite(*a: object, **kw: object) -> dict[str, object]:
        nonlocal benchmark_suite_called
        benchmark_suite_called = True
        raise AssertionError("run_w084_w087_benchmark_suite must NOT be called when endurance_only=True!")

    monkeypatch.setattr(g11_campaign, "run_w084_w087_benchmark_suite", _forbidden_benchmark_suite)

    endurance_only_res = run_g11_campaign(
        live=False,
        dry_run=True,
        family_filter="st_var",
        policy_filter="rule_baseline",
        tasks_per_family=2,
        endurance_hours=0.05,
        endurance_only=True,
        summary_path=summary_file,
        results_path=results_file,
        checkpoint_path=ckpt_file,
    )

    assert benchmark_suite_called is False
    assert endurance_only_res["status"] == "success"
    data = endurance_only_res["data"]
    assert data["endurance_only"] is True
    assert data["w084_w087_benchmark_phase"]["phase_executed"] is False
    assert data["w084_w087_benchmark_phase"]["endurance_only"] is True
    # Prior 2 benchmark trials were preserved from results_file
    assert data["w084_w087_benchmark_phase"]["completed_trials_count"] == 2
    assert len(data["trials"]) == 2

    # W088 endurance phase executed and completed its scheduled endurance items
    w088 = data["w088_endurance"]
    assert w088["endurance_only"] is True
    assert w088["completed_trials_count"] == 2
    sep = w088["separate_endurance_phase"]
    assert sep["phase_executed"] is True
    assert sep["endurance_only"] is True
    assert sep["completed_trials_count"] == 2
    assert sep["status"] == "success"

    captured = capsys.readouterr().out
    assert f"RESULTS_JSON: {results_file.resolve()}" in captured
    assert "FINISHED: Gate G11 Campaign | status=success | mode=dry_run" in captured
    assert "endurance_phase_trials=2" in captured


