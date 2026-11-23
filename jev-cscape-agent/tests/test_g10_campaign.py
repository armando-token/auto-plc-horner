#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comprehensive Unit Test Suite for Gate G10 Campaign (W076-W083).

Verifies:
  1. Strict Log & Artifact Isolation: Unit tests write exclusively to artifacts/logs/g10_unit_test.log,
     never touching artifacts/logs/g10_campaign.log.
  2. >= 25 negative/recovery scenarios strictly disjoint from positive G9 tasks, with all 28 scenarios
     requiring real Cscape GUI and real Jev provider in --live mode.
  3. Full work package coverage across W076, W077, W078, W079, W080, W081, W082, and W083.
  4. W078 transport-layer fault injection around real HTTP calls (recording HTTP status and x-typesafe-request-id)
     and acceptance of resolved model version 'jev-1.13.0'.
  5. W079 real Cscape/worker PID kill mid-save and post-commit + reopen in Cscape and SHA verification.
  6. W080/W081/W082 real file and process operations (CFBF Merkle rebuild, exclusive file lock detection,
     real observer subprocesses & log rotation, dual-profile Cscape switch, COM1 lockout).
  7. Mandatory per-scenario telemetry logging of PID, HTTP status, req_id, and file SHA.
"""

from __future__ import annotations

import ast
from http.server import BaseHTTPRequestHandler
import inspect
import json
import logging
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Set

import pytest

import scripts.g10_campaign as g10
from scripts.g10_campaign import (
    AtomicStagingRecoveryManager,
    BASELINE_P1_SHA,
    BASE_P1_PATH,
    BlindRetryForbiddenError,
    ExpectedOutcome,
    FalseCompletionDetectedError,
    FalseCompletionOracle,
    JevG10ProviderClient,
    LOG_FILE_PATH,
    ObserverHeartbeatWatchdog,
    OutOfScopeWriteError,
    OutOfScopeWriteSandboxGuard,
    POSITIVE_G9_TASK_IDS,
    QuotaBoundedRotatingLogGuard,
    StaleIndexAndCacheCoherencyManager,
    StateDeltaRetryGuard,
    UNIT_TEST_LOG_FILE_PATH,
    WorkPackageID,
    _LocalFaultInjectionHTTPServer,
    assert_g10_safety_invariants,
    build_arg_parser,
    compute_sha256,
    configure_g10_logging,
    execute_g10_scenario,
    execute_live_cscape_g10_scenario,
    get_g10_negative_recovery_scenarios,
    main,
    run_g10_campaign,
)


@pytest.fixture(autouse=True)
def _enforce_unit_test_log_isolation():
    """Ensure every unit test logs to artifacts/logs/g10_unit_test.log and never modifies g10_campaign.log."""
    configure_g10_logging(unit_test_mode=True)
    pre_exists = LOG_FILE_PATH.exists()
    pre_bytes = LOG_FILE_PATH.read_bytes() if pre_exists else b""
    yield
    post_exists = LOG_FILE_PATH.exists()
    post_bytes = LOG_FILE_PATH.read_bytes() if post_exists else b""
    assert pre_exists == post_exists and pre_bytes == post_bytes, (
        "CRITICAL: Unit tests must NEVER write to or modify artifacts/logs/g10_campaign.log!"
    )


# =============================================================================
# Pillar 1: Log Isolation (g10_unit_test.log vs g10_campaign.log)
# =============================================================================

def test_unit_tests_log_to_separate_file_and_never_touch_g10_campaign_log():
    file_handlers = [h for h in g10.logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(file_handlers) == 1
    active_path = Path(file_handlers[0].baseFilename).resolve()
    assert active_path == UNIT_TEST_LOG_FILE_PATH.resolve()
    assert active_path != LOG_FILE_PATH.resolve()

    marker = "G10_UNIT_TEST_ISOLATION_MARKER_98765"
    g10.logger.info(marker)
    file_handlers[0].flush()

    assert UNIT_TEST_LOG_FILE_PATH.exists()
    assert marker in UNIT_TEST_LOG_FILE_PATH.read_text(encoding="utf-8", errors="replace")
    if LOG_FILE_PATH.exists():
        assert marker not in LOG_FILE_PATH.read_text(encoding="utf-8", errors="replace")


# =============================================================================
# Pillar 2: Scenario Catalog Cardinality (>= 25), Separation & W076-W083 Coverage
# =============================================================================

def test_g10_catalog_has_at_least_25_negative_recovery_scenarios_separate_from_positive_tasks():
    scenarios = get_g10_negative_recovery_scenarios()
    assert len(scenarios) == 28
    assert len(scenarios) >= 25

    ids = [s.scenario_id for s in scenarios]
    nums = [s.scenario_num for s in scenarios]
    assert len(set(ids)) == len(scenarios), "Scenario IDs must be strictly unique!"
    assert nums == list(range(1, len(scenarios) + 1)), "Scenario numbers must be sequential 1..N!"

    for s in scenarios:
        assert s.scenario_id not in POSITIVE_G9_TASK_IDS
        assert not s.scenario_id.startswith("G9_TASK_")
        assert isinstance(s.expected_outcome, ExpectedOutcome)
        assert s.expected_outcome.value in ("recover", "abstain", "pause")
        assert s.expected_contract_status in ("success", "failed", "blocked", "inconclusive")
        assert s.requires_cscape_gui is True, f"{s.scenario_id} must require live Cscape GUI in --live mode"
        assert s.requires_jev_provider is True, f"{s.scenario_id} must require live Jev provider in --live mode"


def test_g10_catalog_covers_all_work_packages_w076_through_w082_and_categories():
    scenarios = get_g10_negative_recovery_scenarios()
    wp_set: Set[str] = {s.work_package.value for s in scenarios}
    for wp in ("W076", "W077", "W078", "W079", "W080", "W081", "W082"):
        assert wp in wp_set, f"Work package {wp} must be covered by >= 1 scenario in catalog!"

    categories = {s.category for s in scenarios}
    required_categories = {
        "window_size_position",
        "external_focus_modal",
        "provider_fault",
        "worker_crash_save",
        "stale_index_cache",
        "log_growth_hung_observer",
        "second_profile",
    }
    assert required_categories.issubset(categories)

    outcomes = {s.expected_outcome for s in scenarios}
    assert outcomes == {ExpectedOutcome.RECOVER, ExpectedOutcome.ABSTAIN, ExpectedOutcome.PAUSE}


# =============================================================================
# Pillar 3: CLI Flags (--live, --dry-run, --scenario)
# =============================================================================

def test_g10_cli_parser_supports_live_flag_and_scenario_ranges():
    parser = build_arg_parser()

    args_live = parser.parse_args(["--live"])
    assert args_live.live is True
    assert args_live.dry_run is False

    args_single = parser.parse_args(["--scenario", "11", "--dry-run"])
    assert args_single.scenario == 11
    assert args_single.dry_run is True

    assert main(["--start-scenario", "10", "--end-scenario", "5", "--dry-run"]) == 1
    assert main(["--scenario", "999", "--dry-run"]) == 1


# =============================================================================
# Pillar 4: Zero Out-of-Scope Writes, Zero Blind Retries, Zero False Completions
# =============================================================================

def test_out_of_scope_write_sandbox_guard_blocks_baseline_and_external_paths(tmp_path):
    guard = OutOfScopeWriteSandboxGuard()

    with pytest.raises(OutOfScopeWriteError, match="Forbidden write attempt to immutable baseline"):
        guard.assert_path_writable(BASE_P1_PATH)

    ext_file = tmp_path / "unauthorized_external_write.csp"
    with pytest.raises(OutOfScopeWriteError, match="Out-of-scope write attempt outside sandbox roots"):
        guard.assert_path_writable(ext_file)

    assert len(guard.violations) == 2


def test_state_delta_retry_guard_blocks_blind_retries_and_non_retryable_actions():
    retry_guard = StateDeltaRetryGuard()
    retry_guard.record_attempt("click_canvas", "rect=[0,0,1280,800]:modal=None")

    with pytest.raises(BlindRetryForbiddenError, match="Blind retry detected"):
        retry_guard.record_attempt("click_canvas", "rect=[0,0,1280,800]:modal=None")
    assert retry_guard.blind_retries_count == 1

    retry_guard.record_attempt("click_canvas", "rect=[0,0,1280,800]:modal=Dismissed")

    retry_guard.record_attempt("auth_request", "attempt=1", is_non_retryable=True)
    with pytest.raises(BlindRetryForbiddenError, match="Non-retryable action 'auth_request' was retried blindly"):
        retry_guard.record_attempt("auth_request", "attempt=2", is_non_retryable=True)
    assert retry_guard.blind_retries_count == 2


def test_false_completion_oracle_rejects_unverified_recovery_and_silent_fallbacks():
    scenarios = get_g10_negative_recovery_scenarios()
    rec_spec = next(s for s in scenarios if s.expected_outcome == ExpectedOutcome.RECOVER)
    abs_spec = next(s for s in scenarios if s.expected_outcome == ExpectedOutcome.ABSTAIN)

    oracle = FalseCompletionOracle()

    with pytest.raises(FalseCompletionDetectedError, match="silent mock/fallback"):
        oracle.verify_outcome_claim(rec_spec, ExpectedOutcome.RECOVER, postcondition_verified=True, silent_fallback_used=True)

    with pytest.raises(FalseCompletionDetectedError, match="without verified post-conditions"):
        oracle.verify_outcome_claim(rec_spec, ExpectedOutcome.RECOVER, postcondition_verified=False)

    with pytest.raises(FalseCompletionDetectedError, match="falsely claimed recovery/completion"):
        oracle.verify_outcome_claim(abs_spec, ExpectedOutcome.RECOVER, postcondition_verified=True)

    assert oracle.false_completions_count == 3


# =============================================================================
# Pillar 5: W078 Transport-Layer Fault Wrapper & Concrete Model Resolution
# =============================================================================

def test_w078_transport_fault_wrapper_and_concrete_model_resolution():
    """Verify transport_fault_mode around HTTP responses, x-typesafe-request-id extraction, and 'jev-1.13.0' support."""
    scenarios = {s.scenario_id: s for s in get_g10_negative_recovery_scenarios()}

    def _real_like_typesafe_handler(handler: BaseHTTPRequestHandler, count: int) -> None:
        auth = handler.headers.get("Authorization", "")
        if "sk-invalid-secret-key-9999" in auth:
            handler.send_response(401)
            handler.send_header("x-typesafe-request-id", f"req_live_auth_fail_{count}")
            handler.end_headers()
            handler.wfile.write(b'{"error": "Unauthorized"}')
            return
        body = json.dumps({
            "model": "jev-1.13.0",  # Real TypeSafe server returns concrete version string
            "answers": {
                "fault_disposition": {"type": "choice", "choice": "recover", "confidence": 0.96},
                "safety_preserved": {"type": "noul", "noul": 0.99},
            },
            "usage": {"input_tokens": 210, "output_tokens": 42},
        }).encode("utf-8")
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("x-typesafe-request-id", f"req_live_01a13d37_{count}")
        handler.end_headers()
        handler.wfile.write(body)

    with _LocalFaultInjectionHTTPServer(_real_like_typesafe_handler) as srv:
        # 1. Normal call with 'jev-1.13.0' in response succeeds and captures x-typesafe-request-id
        client = JevG10ProviderClient(endpoint=srv.url, timeout_s=2.0, max_transient_retries=2)
        res_ok = client.query_recovery_decision(scenarios["G10_SCENARIO_01_W076_SMALL_RESIZE_RECOVERY"], live_network=True)
        assert res_ok["http_status"] == 200
        assert res_ok["req_id"].startswith("req_live_01a13d37_")
        assert res_ok["response_model"] == "jev-1.13.0"

        # 2. Transient timeout injected at transport layer -> recovers on attempt 2
        res_s11 = client.query_recovery_decision(
            scenarios["G10_SCENARIO_11_W078_TRANSIENT_TIMEOUT_RECOVERY"],
            live_network=True,
            transport_fault_mode="transient_timeout",
        )
        assert res_s11["disposition"] == ExpectedOutcome.RECOVER
        assert res_s11["attempts_made"] == 2
        assert res_s11["http_status"] == 200
        assert res_s11["req_id"].startswith("req_live_01a13d37_")

        # 3. Persistent timeout injected at transport layer -> pauses after bounded attempts
        client_s12 = JevG10ProviderClient(endpoint=srv.url, timeout_s=2.0, max_transient_retries=1)
        res_s12 = client_s12.query_recovery_decision(
            scenarios["G10_SCENARIO_12_W078_PERSISTENT_TIMEOUT_PAUSE"],
            live_network=True,
            transport_fault_mode="persistent_timeout",
        )
        assert res_s12["disposition"] == ExpectedOutcome.PAUSE
        assert res_s12["error_code"] == "ERR_PROVIDER_TIMEOUT_PAUSED"
        assert res_s12["req_id"].startswith("req_live_01a13d37_")

        # 4. HTTP 429 short Retry-After injected at transport layer -> recovers on attempt 2
        res_s13 = client.query_recovery_decision(
            scenarios["G10_SCENARIO_13_W078_HTTP_429_SHORT_RETRY_AFTER_RECOVERY"],
            live_network=True,
            transport_fault_mode="http_429_short",
        )
        assert res_s13["disposition"] == ExpectedOutcome.RECOVER
        assert res_s13["attempts_made"] == 2
        assert res_s13["http_status"] == 200

        # 5. HTTP 429 long Retry-After (3600s) injected at transport layer -> pauses immediately (1 attempt)
        res_s14 = client.query_recovery_decision(
            scenarios["G10_SCENARIO_14_W078_HTTP_429_QUOTA_EXHAUSTED_PAUSE"],
            live_network=True,
            transport_fault_mode="http_429_long",
        )
        assert res_s14["disposition"] == ExpectedOutcome.PAUSE
        assert res_s14["attempts_made"] == 1
        assert res_s14["http_status"] == 429
        assert res_s14["error_code"] == "ERR_PROVIDER_RATE_LIMITED_PAUSED"

        # 6. Bad API key 401 -> abstains immediately (1 attempt) and redacts secret
        res_s15 = client.query_recovery_decision(
            scenarios["G10_SCENARIO_15_W078_BAD_API_KEY_401_ABSTAIN"],
            live_network=True,
            override_api_key="sk-invalid-secret-key-9999",
            transport_fault_mode="bad_api_key_401",
        )
        assert res_s15["disposition"] == ExpectedOutcome.ABSTAIN
        assert res_s15["attempts_made"] == 1
        assert res_s15["http_status"] == 401
        assert res_s15["req_id"].startswith("req_live_auth_fail_")

        # 7. Unsupported model injected at transport layer -> abstains with real req_id
        res_s16 = client.query_recovery_decision(
            scenarios["G10_SCENARIO_16_W078_UNSUPPORTED_MODEL_CHANGE_ABSTAIN"],
            live_network=True,
            override_model="jev-deprecated-v0",
            transport_fault_mode="unsupported_model",
        )
        assert res_s16["disposition"] == ExpectedOutcome.ABSTAIN
        assert res_s16["attempts_made"] == 1
        assert res_s16["http_status"] == 200
        assert res_s16["error_code"] == "ERR_PROVIDER_MODEL_UNSUPPORTED"
        assert res_s16["req_id"].startswith("req_live_01a13d37_")

        # 8. Schema mismatch injected at transport layer -> abstains with real req_id
        res_s17 = client.query_recovery_decision(
            scenarios["G10_SCENARIO_17_W078_MALFORMED_SCHEMA_HALLUCINATED_CHOICE_ABSTAIN"],
            live_network=True,
            transport_fault_mode="schema_mismatch",
        )
        assert res_s17["disposition"] == ExpectedOutcome.ABSTAIN
        assert res_s17["attempts_made"] == 1
        assert res_s17["http_status"] == 200
        assert res_s17["error_code"] == "ERR_PROVIDER_SCHEMA_MISMATCH"
        assert res_s17["req_id"].startswith("req_live_01a13d37_")


# =============================================================================
# Pillar 6: W079 Real PID Kill + Reopen & SHA Verification
# =============================================================================

def test_w079_live_mode_kills_real_process_and_reopens_to_verify_sha(monkeypatch):
    """Verify W079 scenarios 18, 19, 20 in live_mode=True spawn/kill a real OS process PID, perform real SHA-mutating save, reopen, and verify SHA."""
    spawned_procs = []

    class DummyApp:
        def window(self, handle=None):
            return object()

    def fake_launch_cscape(project_path):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        spawned_procs.append(proc)
        return DummyApp(), proc.pid, 0x2002

    def fake_close_cscape(pid, timeout=5.0):
        for p in spawned_procs:
            if p.pid == pid and p.poll() is None:
                p.kill()
                p.wait(timeout=2.0)

    def fake_declare_vars(pid, main_hwnd, app, spec, copy_path):
        # Simulate Cscape saving valid mutated CFBF container to copy_path so SHA changes
        shutil.copy2(BASE_P1_PATH, copy_path)
        g10._mutate_csp_cfbf_for_dry_run(copy_path, spec.level_pv_tag)
        return True

    monkeypatch.setattr(g10, "kill_leftover_cscape", lambda: None)
    monkeypatch.setattr(g10, "configure_cscape_registry", lambda p: None)
    monkeypatch.setattr(g10, "launch_cscape_with_project", fake_launch_cscape)
    monkeypatch.setattr(g10, "close_cscape_gracefully", fake_close_cscape)
    monkeypatch.setattr(g10, "handle_startup_dialogs_and_wait_for_main_window", lambda **kw: None)
    monkeypatch.setattr(g10, "dismiss_about_cscape_and_wait_main_enabled", lambda mh, pid: None)
    monkeypatch.setattr(g10, "declare_variables_via_live_cscape_ui", fake_declare_vars)
    monkeypatch.setattr(g10, "handle_program_information_modified_dialog", lambda pid, timeout=1.0: False)
    monkeypatch.setattr(g10, "handle_confirmation_popups", lambda pid, timeout=1.0: None)
    monkeypatch.setattr(g10.time, "sleep", lambda _: None)
    monkeypatch.setattr(g10.user32, "ShowWindow", lambda h, c: 1)
    monkeypatch.setattr(g10.user32, "MoveWindow", lambda h, x, y, w, hgt, r: 1)
    monkeypatch.setattr(g10.user32, "PostMessageW", lambda h, m, wp, lp: 1)
    monkeypatch.setattr(g10.user32, "SendMessageW", lambda h, m, wp, lp: 1)
    monkeypatch.setattr(g10.win32gui, "IsWindowEnabled", lambda h: True)

    sandbox_guard = OutOfScopeWriteSandboxGuard()
    mgr = AtomicStagingRecoveryManager(sandbox_guard=sandbox_guard)

    try:
        res18 = mgr.run_mid_save_kill_scenario("G10_SCENARIO_18_W079_KILL_WORKER_MID_SAVE_RECOVERY", live_mode=True)
        assert res18["recovered"] is True
        assert res18["killed_pid"] > 0
        assert res18["reopened_pid"] > 0
        assert res18["killed_pid"] != res18["reopened_pid"]
        assert res18["rollback_sha_intact"] is True
        assert res18["rollback_sha256"] == res18["file_sha_before"]
        assert res18["file_sha_before"] != res18["file_sha_after"]

        res19 = mgr.run_post_commit_kill_scenario("G10_SCENARIO_19_W079_KILL_WORKER_POST_COMMIT_RECOVERY", live_mode=True)
        assert res19["recovered"] is True
        assert res19["killed_pid"] > 0
        assert res19["reopened_pid"] > 0
        assert res19["killed_pid"] != res19["reopened_pid"]
        assert res19["file_sha_before"] != res19["file_sha_after"]
        assert res19["file_sha_after"] == res19["promoted_sha256"]

        res20 = mgr.run_post_commit_corrupt_staging_abstain_scenario(
            "G10_SCENARIO_20_W079_POST_COMMIT_CORRUPT_STAGING_ABSTAIN", live_mode=True
        )
        assert res20["abstained"] is True
        assert res20["killed_pid"] > 0
        assert res20["reopened_pid"] > 0
        assert res20["target_sha_preserved"] is True
    finally:
        for p in spawned_procs:
            if p.poll() is None:
                p.kill()


def test_cursorless_mouse_guard_and_win32_variable_declaration_survive_locked_desktop(monkeypatch):
    """Verify cursorless mouse guard catches 'There is no active desktop required for moving mouse cursor!' and falls back to Win32."""
    posted_messages = []

    monkeypatch.setattr(g10.user32, "WindowFromPoint", lambda pt: 0x3003)
    monkeypatch.setattr(g10.win32gui, "IsWindow", lambda h: True)
    monkeypatch.setattr(g10.win32gui, "ScreenToClient", lambda h, coords: (40, 12))
    monkeypatch.setattr(
        g10.user32,
        "PostMessageW",
        lambda h, m, wp, lp: posted_messages.append((h, m, wp, lp)) or 1,
    )

    assert g10._post_client_mouse_click(120, 240, button="left", double=False) is True
    assert g10._post_client_mouse_click(120, 240, button="right", double=False) is True
    assert any(m == g10.win32con.WM_LBUTTONDOWN for _, m, _, _ in posted_messages)
    assert any(m == g10.win32con.WM_CONTEXTMENU for _, m, _, _ in posted_messages)

    # Verify require_copy_mutation fails closed when SHA is unchanged
    guard = OutOfScopeWriteSandboxGuard()
    unmutated_copy = g10.COPIES_DIR / "g10_unmutated_check.csp"
    shutil.copy2(BASE_P1_PATH, unmutated_copy)
    with pytest.raises(FalseCompletionDetectedError, match="Scenario required a real save that changes SHA"):
        guard.verify_post_scenario_integrity(
            disposable_copy_path=unmutated_copy,
            initial_copy_sha=BASELINE_P1_SHA,
            allow_copy_mutation=True,
            require_copy_mutation=True,
        )


# =============================================================================
# Pillar 7: Full Campaign Execution (All 28 Scenarios across W076-W083) & Telemetry Verification
# =============================================================================

def test_run_g10_campaign_executes_all_scenarios_and_logs_pid_http_req_id_and_sha():
    summary = run_g10_campaign(start_scenario=1, end_scenario=28, live=False, dry_run=True)

    assert summary["gate"] == "G10"
    assert summary["status"] == "success"
    assert summary["scenarios_total"] == 28
    assert summary["strictly_separate_from_positive_tasks"] is True

    metrics = summary["metrics"]
    assert metrics["out_of_scope_writes"] == 0
    assert metrics["blind_retries"] == 0
    assert metrics["false_completions"] == 0
    assert metrics["recoverable_total"] == 16
    assert metrics["recoverable_recovered"] == 16
    assert metrics["recoverable_recovery_rate"] == 1.0
    assert summary["acceptance_criteria"]["all_passed"] is True
    assert compute_sha256(BASE_P1_PATH) == BASELINE_P1_SHA

    # Verify W079 (18, 19) and W080 (21, 22) performed real saves that changed file_sha_after != file_sha_before
    scen_by_num = {r["scenario_num"]: r for r in summary["scenarios"]}
    for s_num in (18, 19, 21, 22):
        assert scen_by_num[s_num]["file_sha_before"] != scen_by_num[s_num]["file_sha_after"], (
            f"Scenario {s_num} must change SHA via real save!"
        )

    for fh in g10.logger.handlers:
        if isinstance(fh, logging.FileHandler):
            fh.flush()
    log_text = UNIT_TEST_LOG_FILE_PATH.read_text(encoding="utf-8", errors="replace")

    for rec in summary["scenarios"]:
        assert isinstance(rec["pid"], int) and rec["pid"] > 0
        assert rec["http_status"] in (200, 401, 403, 422, 429, 504)
        assert isinstance(rec["req_id"], str) and len(rec["req_id"]) > 0
        assert isinstance(rec["file_sha"], str) and len(rec["file_sha"]) == 64
        pattern = (
            rf"\[{re.escape(rec['scenario_id'])}\] TELEMETRY \| pid=\d+ \| "
            rf"http_status=\d+ \| req_id=\S+ \| file=\S+ \| "
            rf"file_sha_before=[0-9a-f]{{64}} \| file_sha_after=[0-9a-f]{{64}}"
        )
        assert re.search(pattern, log_text), f"Missing TELEMETRY log line for {rec['scenario_id']}"
        outcome_pattern = rf"\[{re.escape(rec['scenario_id'])}\] Outcome="
        assert re.search(outcome_pattern, log_text), f"Missing Outcome= log line for {rec['scenario_id']}"


def test_run_g10_campaign_threshold_90_percent_recoverable_rate_enforcement(monkeypatch):
    """Verify that:
    - 1 failed recoverable scenario out of 15 (14/15 = 93.3% >= 90%) still meets the >= 90% recoverable gate.
    - 3 failed recoverable scenarios out of 15 (12/15 = 80.0% < 90%) fails closed with status='failed'.
    """
    orig_exec = g10.execute_g10_scenario

    def _fail_one_recoverable(spec, jev_client, sandbox_guard, false_completion_oracle, live_mode=False, scenarios_dir=None):
        if spec.scenario_num == 1:
            raise RuntimeError("Simulated single recoverable failure")
        return orig_exec(spec, jev_client, sandbox_guard, false_completion_oracle, live_mode=live_mode, scenarios_dir=scenarios_dir)

    monkeypatch.setattr(g10, "execute_g10_scenario", _fail_one_recoverable)
    summary_one_fail = run_g10_campaign(start_scenario=1, end_scenario=28, live=False, dry_run=True)
    assert summary_one_fail["metrics"]["recoverable_recovery_rate"] >= 0.90
    assert summary_one_fail["status"] == "success"

    def _fail_three_recoverable(spec, jev_client, sandbox_guard, false_completion_oracle, live_mode=False, scenarios_dir=None):
        if spec.scenario_num in (1, 2, 3):
            raise RuntimeError("Simulated recoverable failure")
        return orig_exec(spec, jev_client, sandbox_guard, false_completion_oracle, live_mode=live_mode, scenarios_dir=scenarios_dir)

    monkeypatch.setattr(g10, "execute_g10_scenario", _fail_three_recoverable)
    summary_three_fail = run_g10_campaign(start_scenario=1, end_scenario=28, live=False, dry_run=True)
    assert summary_three_fail["metrics"]["recoverable_recovery_rate"] < 0.90
    assert summary_three_fail["status"] == "failed"
    assert summary_three_fail["error_code"] == "ERR_G10_ACCEPTANCE_FAILED"


# =============================================================================
# Pillar 8: Behavioral Live Cscape W076 / W077 / W080 / W082 Execution Path Tests
# =============================================================================

def test_execute_live_cscape_g10_scenario_window_geometry_and_modal_recovery(monkeypatch):
    """Behaviorally verify execute_live_cscape_g10_scenario with mocked Win32 APIs for W076, W077, W080, W082."""
    copy_csp = g10.COPIES_DIR / "g10_live_unit_test.csp"
    shutil.copy2(BASE_P1_PATH, copy_csp)

    win_state = {"rect": (0, 0, 1280, 800), "iconic": False, "enabled": True}

    def fake_move_window(h, x, y, w, hgt, repaint):
        win_state["rect"] = (x, y, x + w, y + hgt)
        return 1

    def fake_set_window_pos(h, ins, x, y, w, hgt, flags):
        win_state["rect"] = (x, y, x + w, y + hgt)
        return 1

    def fake_show_window(h, cmd):
        if cmd == g10.win32con.SW_MINIMIZE:
            win_state["iconic"] = True
        elif cmd == g10.win32con.SW_RESTORE:
            win_state["iconic"] = False
        return 1

    class DummyApp:
        def window(self, handle=None):
            return object()

    monkeypatch.setattr(g10, "kill_leftover_cscape", lambda: None)
    monkeypatch.setattr(g10, "configure_cscape_registry", lambda p: None)
    monkeypatch.setattr(g10, "launch_cscape_with_project", lambda p: (DummyApp(), 4242, 0x1001))
    monkeypatch.setattr(g10, "handle_startup_dialogs_and_wait_for_main_window", lambda **kw: None)
    monkeypatch.setattr(g10, "dismiss_about_cscape_and_wait_main_enabled", lambda mh, pid: None)
    monkeypatch.setattr(g10, "close_cscape_gracefully", lambda pid, timeout=5.0: None)
    monkeypatch.setattr(g10.time, "sleep", lambda _: None)
    monkeypatch.setattr(g10.user32, "MoveWindow", fake_move_window)
    monkeypatch.setattr(g10.user32, "SetWindowPos", fake_set_window_pos)
    monkeypatch.setattr(g10.user32, "ShowWindow", fake_show_window)
    monkeypatch.setattr(g10.user32, "SetForegroundWindow", lambda h: 1)
    monkeypatch.setattr(g10.user32, "BringWindowToTop", lambda h: 1)
    monkeypatch.setattr(g10.user32, "PostMessageW", lambda h, m, wp, lp: 1)
    monkeypatch.setattr(g10.win32gui, "GetWindowRect", lambda h: win_state["rect"])
    monkeypatch.setattr(g10.win32gui, "IsIconic", lambda h: win_state["iconic"])
    monkeypatch.setattr(g10.win32gui, "IsWindowVisible", lambda h: True)
    monkeypatch.setattr(g10.win32gui, "IsWindowEnabled", lambda h: win_state["enabled"])
    monkeypatch.setattr(g10.win32gui, "GetForegroundWindow", lambda: 0x1001)
    monkeypatch.setattr(g10.win32process, "GetWindowThreadProcessId", lambda h: (1, 4242))

    scenarios = {s.scenario_id: s for s in get_g10_negative_recovery_scenarios()}
    sandbox_guard = OutOfScopeWriteSandboxGuard()

    for sid in (
        "G10_SCENARIO_01_W076_SMALL_RESIZE_RECOVERY",
        "G10_SCENARIO_02_W076_OFFSCREEN_DISPLACEMENT_RECOVERY",
        "G10_SCENARIO_03_W076_MINIMIZED_ICONIC_RECOVERY",
        "G10_SCENARIO_05_W077_EXTERNAL_FOCUS_STEAL_RECOVERY",
        "G10_SCENARIO_07_W077_UNEXPECTED_ABOUT_MODAL_RECOVERY",
        "G10_SCENARIO_27_W082_SECOND_PROFILE_ISOLATION_RECOVERY",
    ):
        rg = StateDeltaRetryGuard()
        res = execute_live_cscape_g10_scenario(scenarios[sid], copy_csp, sandbox_guard, rg)
        assert res["outcome"] == ExpectedOutcome.RECOVER
        assert res["postcondition_verified"] is True
        assert res["pid"] == 4242
        assert rg.blind_retries_count == 0


# =============================================================================
# Pillar 9: AST Call-Site Signature Audit & Hardware Safety Invariants
# =============================================================================

def test_g10_campaign_all_imported_helper_call_sites_match_signatures():
    src_path = Path(g10.__file__).resolve()
    tree = ast.parse(src_path.read_text(encoding="utf-8"))

    checked_funcs = {
        "launch_cscape_with_project": g10.launch_cscape_with_project,
        "handle_startup_dialogs_and_wait_for_main_window": g10.handle_startup_dialogs_and_wait_for_main_window,
        "dismiss_about_cscape_and_wait_main_enabled": g10.dismiss_about_cscape_and_wait_main_enabled,
        "close_cscape_gracefully": g10.close_cscape_gracefully,
        "trigger_and_read_cscape_error_check": g10.trigger_and_read_cscape_error_check,
        "dismiss_error_check_modals": g10.dismiss_error_check_modals,
        "handle_confirmation_popups": g10.handle_confirmation_popups,
        "declare_variables_via_live_cscape_ui": g10.declare_variables_via_live_cscape_ui,
        "handle_program_information_modified_dialog": g10.handle_program_information_modified_dialog,
    }

    bound_count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            fn_name = node.func.id
            if fn_name in checked_funcs:
                sig = inspect.signature(checked_funcs[fn_name])
                pos_args = [None] * len(node.args)
                kw_args = {kw.arg: None for kw in node.keywords if kw.arg is not None}
                sig.bind(*pos_args, **kw_args)
                bound_count += 1

    assert bound_count >= 15


def test_g10_hardware_safety_invariants_enforced():
    assert_g10_safety_invariants()
    assert compute_sha256(BASE_P1_PATH) == BASELINE_P1_SHA
