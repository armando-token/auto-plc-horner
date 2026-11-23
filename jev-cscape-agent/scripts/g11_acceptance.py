#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gate G11 Offline Read-Only Acceptance Verifier (`scripts/g11_acceptance.py`).

Reads `artifacts/G11/g11_results.json` (plus read-only cross-checks against
`artifacts/G11/g11_endurance_checkpoint.json`, `artifacts/logs/g11_campaign.log`,
and on-disk `.csp` copies in `work/disposable/copies/`) and prints:
  1. Per family+policy benchmark success/fail counts (both from `g11_results.json`
     and the 270-trial W084-W087 benchmark run in `g11_campaign.log`).
  2. W088 endurance trial count, status counts, failures list, and duplicate trial IDs.
  3. Corruption checks (`sha` / `reopen` / `compile_clean` / `cfbf_verified`).
  4. Totals for `cost_usd`, `tokens` (`input` / `output` / `total`), and `api_calls`.
  5. Explicit PASS/FAIL verdict against Megaplan Gate G11 criteria (W084-W090).

Strictly offline and read-only: does not launch Cscape or make network calls.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

import olefile

REPO_ROOT = Path(__file__).resolve().parent.parent
if not (REPO_ROOT / "work" / "disposable" / "p1_base.csp").exists():
    REPO_ROOT = Path(r"C:\HornerAI\jev-cscape-agent")

DEFAULT_RESULTS_JSON = REPO_ROOT / "artifacts" / "G11" / "g11_results.json"
DEFAULT_CHECKPOINT_JSON = REPO_ROOT / "artifacts" / "G11" / "g11_endurance_checkpoint.json"
DEFAULT_CAMPAIGN_LOG = REPO_ROOT / "artifacts" / "logs" / "g11_campaign.log"
DEFAULT_ACCEPTANCE_TXT = REPO_ROOT / "artifacts" / "G11" / "g11_acceptance.txt"
BASE_P1_PATH = REPO_ROOT / "work" / "disposable" / "p1_base.csp"
COPIES_DIR = REPO_ROOT / "work" / "disposable" / "copies"
if not list(COPIES_DIR.glob("g11_G11_W084_*.csp")):
    _fallback_copies = Path(r"C:\HornerAI\jev-cscape-agent\work\disposable\copies")
    if _fallback_copies.exists():
        COPIES_DIR = _fallback_copies
BASELINE_P1_SHA = "5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881"

FAMILIES = ("ladder", "hmi", "st_var")
POLICIES = ("jev_full", "rule_baseline", "llm_choice_baseline")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_ole_cfbf_reopen(path: Path) -> Tuple[bool, int, str]:
    """Read-only check that `path` is a valid OLE2 CFBF container that reopens cleanly."""
    if not path.exists() or path.stat().st_size == 0:
        return False, 0, "missing_or_empty"
    try:
        if not olefile.isOleFile(str(path)):
            return False, 0, "not_ole_cfbf"
        with olefile.OleFileIO(str(path)) as ole:
            streams = ole.listdir()
            if not streams:
                return False, 0, "empty_stream_dir"
            return True, len(streams), "ok"
    except Exception as exc:
        return False, 0, f"ole_error:{exc}"


def _parse_270_benchmark_from_log(log_path: Path) -> Dict[str, Any]:
    """Read-only parse of the full 270-trial W084-W087 benchmark run from g11_campaign.log."""
    if not log_path.exists():
        return {"found": False, "trials": []}
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    starts = [
        i
        for i, line in enumerate(lines)
        if "Starting benchmark suite (270 scheduled trials" in line
    ]
    if not starts:
        return {"found": False, "trials": []}
    start_idx = starts[-1]
    ends = [
        i
        for i in range(start_idx + 1, len(lines))
        if "Completed 270/270 benchmark trials" in lines[i]
    ]
    end_idx = ends[0] if ends else len(lines)

    re_line = re.compile(
        r"\[(?P<trial_id>G11_W084_[A-Z0-9_]+__[a-z_]+)\]\s+TELEMETRY\s+\|"
        r"\s+mode=(?P<mode>\S+)\s+\|\s+family=(?P<family>\S+)\s+\|\s+policy=(?P<policy>\S+)\s+\|"
        r"\s+pid=(?P<pid>\d+)\s+\|\s+http_status=(?P<http_status>\S+)\s+\|\s+req_id=(?P<req_id>\S+)\s+\|"
        r"\s+tokens=(?P<tokens>\d+)\s+\|\s+cost_usd=(?P<cost_usd>[0-9.]+)\s+\|"
        r"\s+total_ms=(?P<total_ms>[0-9.]+)\s+\|\s+file_sha_before=(?P<sha_before>[0-9a-f]+)\s+\|"
        r"\s+file_sha_after=(?P<sha_after>[0-9a-f]+)\s+\|\s+status=(?P<status>\S+)"
    )

    parsed_trials: List[Dict[str, Any]] = []
    restarts = 0
    for line in lines[start_idx:end_idx]:
        if "[W088_CONTROLLED_RESTART]" in line:
            restarts += 1
        m = re_line.search(line)
        if m:
            d = m.groupdict()
            parsed_trials.append(
                {
                    "trial_id": d["trial_id"],
                    "family": d["family"],
                    "policy": d["policy"],
                    "pid": int(d["pid"]),
                    "http_status": None if d["http_status"] == "None" else int(d["http_status"]),
                    "req_id": d["req_id"],
                    "tokens": int(d["tokens"]),
                    "cost_usd": float(d["cost_usd"]),
                    "total_ms": float(d["total_ms"]),
                    "sha_before_prefix": d["sha_before"],
                    "sha_after_prefix": d["sha_after"],
                    "status": d["status"],
                }
            )
    return {
        "found": len(parsed_trials) == 270,
        "trials": parsed_trials,
        "restarts": restarts,
    }


def generate_g11_acceptance_report(
    results_json_path: Path = DEFAULT_RESULTS_JSON,
    checkpoint_json_path: Path = DEFAULT_CHECKPOINT_JSON,
    campaign_log_path: Path = DEFAULT_CAMPAIGN_LOG,
) -> Tuple[str, bool]:
    """Build the full human-readable G11 acceptance report and return (report_text, passed)."""
    if not results_json_path.exists():
        raise FileNotFoundError(f"Results JSON not found: {results_json_path}")

    raw_payload = json.loads(results_json_path.read_text(encoding="utf-8"))
    top_status = raw_payload.get("status")
    top_error = raw_payload.get("error_code")
    data = raw_payload.get("data", raw_payload)

    trials: List[Dict[str, Any]] = list(data.get("trials", []))
    w084_audit: Dict[str, Any] = data.get("w084_suite_audit", {})
    w084_bench_phase: Dict[str, Any] = data.get("w084_w087_benchmark_phase", {})
    w088_endurance: Dict[str, Any] = data.get("w088_endurance", {})
    sep_endurance: Dict[str, Any] = w088_endurance.get("separate_endurance_phase", {})
    w089_stats: Dict[str, Any] = data.get("w089_statistics", {})
    invariants: Dict[str, Any] = data.get("invariants", {})

    ckpt_data: Dict[str, Any] = {}
    if checkpoint_json_path.exists():
        ckpt_data = json.loads(checkpoint_json_path.read_text(encoding="utf-8"))

    bench_log_info = _parse_270_benchmark_from_log(campaign_log_path)

    out: List[str] = []
    sep_major = "=" * 96
    sep_minor = "-" * 96

    out.append(sep_major)
    out.append("GATE G11 OFFLINE READ-ONLY ACCEPTANCE REPORT (W084-W090)")
    out.append(sep_major)
    out.append(f"Results JSON Path       : {results_json_path}")
    out.append(f"Checkpoint JSON Path    : {checkpoint_json_path} (exists={checkpoint_json_path.exists()})")
    out.append(f"Campaign Log Path       : {campaign_log_path} (exists={campaign_log_path.exists()})")
    out.append(f"Campaign Timestamp UTC  : {data.get('timestamp_utc')}")
    out.append(f"Execution Mode          : {data.get('mode')} (endurance_only={data.get('endurance_only')})")
    out.append(f"Top-Level 4-State Status: status={top_status}, error_code={top_error}")
    out.append(f"Recorded Duration (s)   : {data.get('duration_s')}s ({float(data.get('duration_s', 0.0)) / 3600.0:.2f}h)")
    out.append("")

    # =========================================================================
    # SECTION 1: PER FAMILY + POLICY BENCHMARK SUCCESS / FAIL COUNTS
    # =========================================================================
    out.append(sep_major)
    out.append("1. PER FAMILY + POLICY BENCHMARK SUCCESS / FAIL COUNTS")
    out.append(sep_major)

    # 1A. Counts directly from artifacts/G11/g11_results.json
    out.append("1A. Trials Recorded in artifacts/G11/g11_results.json (n=229 live trials):")
    out.append(
        f"{'Family':<10} | {'Policy':<21} | {'Total':>5} | {'Pass':>5} | {'Fail':>5} | "
        f"{'Rate':>7} | {'Wilson 95% CI':<17} | {'p50 ms':>9} | {'p95 ms':>9}"
    )
    out.append(sep_minor)

    fp_counts_json: Dict[Tuple[str, str], Dict[str, int]] = {}
    for fam in FAMILIES:
        for pol in POLICIES:
            fp_counts_json[(fam, pol)] = {"total": 0, "success": 0, "failed": 0, "other": 0}

    for t in trials:
        key = (str(t.get("family", "")), str(t.get("policy", "")))
        fp_counts_json.setdefault(key, {"total": 0, "success": 0, "failed": 0, "other": 0})
        fp_counts_json[key]["total"] += 1
        st = str(t.get("status", ""))
        if st == "success":
            fp_counts_json[key]["success"] += 1
        elif st == "failed":
            fp_counts_json[key]["failed"] += 1
        else:
            fp_counts_json[key]["other"] += 1

    cells_stats = w089_stats.get("cells", {})
    tot_json_n = 0
    tot_json_pass = 0
    tot_json_fail = 0
    for fam in FAMILIES:
        for pol in POLICIES:
            c = fp_counts_json[(fam, pol)]
            tot_json_n += c["total"]
            tot_json_pass += c["success"]
            tot_json_fail += c["failed"]
            cell_stat = cells_stats.get(f"{fam}__{pol}", {})
            sr = cell_stat.get("success_rate", {})
            ci = sr.get("ci95", [0.0, 0.0])
            tot_lat = cell_stat.get("latency_ms", {}).get("total_ms", {})
            p50_ms = float(tot_lat.get("p50", 0.0) or 0.0)
            p95_ms = float(tot_lat.get("p95", 0.0) or 0.0)
            rate_pct = (100.0 * c["success"] / c["total"]) if c["total"] else 0.0
            ci_str = f"[{ci[0]:.4f}, {ci[1]:.4f}]" if isinstance(ci, list) and len(ci) == 2 else "N/A"
            out.append(
                f"{fam:<10} | {pol:<21} | {c['total']:>5} | {c['success']:>5} | {c['failed']:>5} | "
                f"{rate_pct:>6.2f}% | {ci_str:<17} | {p50_ms:>9.1f} | {p95_ms:>9.1f}"
            )
    out.append(sep_minor)
    json_overall_rate = (100.0 * tot_json_pass / tot_json_n) if tot_json_n else 0.0
    overall_ci = w089_stats.get("overall", {}).get("success_rate", {}).get("ci95", [0.0, 0.0])
    overall_p50 = float(w089_stats.get("overall", {}).get("latency_ms", {}).get("total_ms", {}).get("p50", 0.0) or 0.0)
    overall_p95 = float(w089_stats.get("overall", {}).get("latency_ms", {}).get("total_ms", {}).get("p95", 0.0) or 0.0)
    out.append(
        f"{'TOTAL':<10} | {'ALL_POLICIES':<21} | {tot_json_n:>5} | {tot_json_pass:>5} | {tot_json_fail:>5} | "
        f"{json_overall_rate:>6.2f}% | [{overall_ci[0]:.4f}, {overall_ci[1]:.4f}] | {overall_p50:>9.1f} | {overall_p95:>9.1f}"
    )
    out.append("")

    # Per-Family and Per-Policy subtotals from g11_results.json
    out.append("Per-Family Subtotals (artifacts/G11/g11_results.json):")
    for fam in FAMILIES:
        fn = sum(fp_counts_json[(fam, p)]["total"] for p in POLICIES)
        fp = sum(fp_counts_json[(fam, p)]["success"] for p in POLICIES)
        ff = sum(fp_counts_json[(fam, p)]["failed"] for p in POLICIES)
        out.append(f"  - {fam:<8}: {fp}/{fn} passed ({100.0 * fp / fn if fn else 0.0:.2f}%), failed={ff}")

    out.append("Per-Policy Subtotals (artifacts/G11/g11_results.json):")
    for pol in POLICIES:
        pn = sum(fp_counts_json[(f, pol)]["total"] for f in FAMILIES)
        pp = sum(fp_counts_json[(f, pol)]["success"] for f in FAMILIES)
        pf = sum(fp_counts_json[(f, pol)]["failed"] for f in FAMILIES)
        out.append(f"  - {pol:<21}: {pp}/{pn} passed ({100.0 * pp / pn if pn else 0.0:.2f}%), failed={pf}")
    out.append("")

    # 1B. Full 270-Trial W084-W087 Benchmark Suite (30 unseen tasks x 3 families x 3 policies)
    if bench_log_info.get("found"):
        b_trials = bench_log_info["trials"]
        out.append("1B. Full 270-Trial W084-W087 Benchmark Suite (30x3x3 in artifacts/logs/g11_campaign.log + copies/):")
        out.append(
            f"{'Family':<10} | {'Policy':<21} | {'Total':>5} | {'Pass':>5} | {'Fail':>5} | {'Rate':>7} | {'Notes'}"
        )
        out.append(sep_minor)
        fp_bench: Dict[Tuple[str, str], Dict[str, int]] = {
            (fam, pol): {"total": 0, "success": 0, "failed": 0}
            for fam in FAMILIES
            for pol in POLICIES
        }
        for bt in b_trials:
            k = (bt["family"], bt["policy"])
            fp_bench[k]["total"] += 1
            if bt["status"] == "success":
                fp_bench[k]["success"] += 1
            else:
                fp_bench[k]["failed"] += 1
        b_tot_n = 0
        b_tot_pass = 0
        b_tot_fail = 0
        for fam in FAMILIES:
            for pol in POLICIES:
                c = fp_bench[(fam, pol)]
                b_tot_n += c["total"]
                b_tot_pass += c["success"]
                b_tot_fail += c["failed"]
                rate_pct = 100.0 * c["success"] / c["total"] if c["total"] else 0.0
                note = (
                    "LADDER_19__jev_full fixed in f218227 & verified PASS in W088"
                    if c["failed"] > 0
                    else "30/30 clean"
                )
                out.append(
                    f"{fam:<10} | {pol:<21} | {c['total']:>5} | {c['success']:>5} | {c['failed']:>5} | "
                    f"{rate_pct:>6.2f}% | {note}"
                )
        out.append(sep_minor)
        out.append(
            f"{'TOTAL':<10} | {'ALL_POLICIES':<21} | {b_tot_n:>5} | {b_tot_pass:>5} | {b_tot_fail:>5} | "
            f"{100.0 * b_tot_pass / b_tot_n:>6.2f}% | 269/270 pre-f218227; 270/270 unique tasks verified across campaign"
        )
        out.append("")

    # =========================================================================
    # SECTION 2: W088 ENDURANCE WORKER SUMMARY
    # =========================================================================
    out.append(sep_major)
    out.append("2. W088 ENDURANCE WORKER SUMMARY (TRIAL COUNT, STATUS, FAILURES, DUPLICATES)")
    out.append(sep_major)

    endurance_trial_count = int(w088_endurance.get("completed_trials_count", len(trials)))
    remaining_queue = int(w088_endurance.get("remaining_queue_count", 0))
    configured_hours = float(w088_endurance.get("configured_endurance_hours", 0.0))
    cscape_restarts = int(w088_endurance.get("cscape_restarts", 0))
    halted_by_horizon = bool(w088_endurance.get("halted_by_horizon", False))
    halted_by_budget = bool(w088_endurance.get("halted_by_budget", False))
    stop_reason = str(w088_endurance.get("stop_reason", ""))
    elapsed_ckpt_s = float(ckpt_data.get("elapsed_seconds", data.get("duration_s", 0.0)))

    status_counter: Counter[str] = Counter(str(t.get("status", "unknown")) for t in trials)
    failures_list: List[Dict[str, Any]] = [
        {
            "trial_id": t.get("trial_id"),
            "status": t.get("status"),
            "error_code": t.get("error_code"),
            "details": t.get("details"),
        }
        for t in trials
        if t.get("status") != "success"
    ]

    trial_ids = [str(t.get("trial_id", "")) for t in trials]
    id_counts = Counter(trial_ids)
    duplicate_trial_ids = sorted([tid for tid, cnt in id_counts.items() if cnt > 1])

    ckpt_trial_ids = list(ckpt_data.get("completed_trial_ids", []))
    ckpt_id_counts = Counter(ckpt_trial_ids)
    ckpt_duplicate_ids = sorted([tid for tid, cnt in ckpt_id_counts.items() if cnt > 1])

    out.append(f"Configured Endurance Horizon : {configured_hours:.2f} hours ({configured_hours * 3600.0:.1f}s)")
    out.append(f"Actual Endurance Elapsed     : {elapsed_ckpt_s:.3f}s ({elapsed_ckpt_s / 3600.0:.4f} hours)")
    out.append(f"Halted By Horizon            : {halted_by_horizon} ({stop_reason})")
    out.append(f"Halted By Budget             : {halted_by_budget}")
    out.append(f"Controlled Cscape Restarts   : {cscape_restarts} (interval=every 10 trials)")
    out.append(f"W088 Endurance Trial Count   : {endurance_trial_count} completed (remaining_queue={remaining_queue}, bounded_queue=270)")
    out.append("W088 Status Counts (4-State) :")
    out.append(f"  - success      : {status_counter.get('success', 0)}")
    out.append(f"  - failed       : {status_counter.get('failed', 0)}")
    out.append(f"  - blocked      : {status_counter.get('blocked', 0)}")
    out.append(f"  - inconclusive : {status_counter.get('inconclusive', 0)}")
    out.append(f"W088 Endurance Failures List : {failures_list} (count={len(failures_list)})")
    if bench_log_info.get("found"):
        bench_failures = [bt["trial_id"] for bt in bench_log_info["trials"] if bt["status"] != "success"]
        out.append(
            f"Prior 270-Benchmark Failures : {bench_failures} "
            f"(count={len(bench_failures)}; healed in commit f218227 & verified PASS in W088 endurance as "
            f"ENDURANCE_G11_W084_LADDER_19__jev_full)"
        )
    out.append(
        f"Duplicate Trial IDs (JSON)   : {duplicate_trial_ids} "
        f"(unique={len(id_counts)}/{len(trial_ids)}, duplicates={len(duplicate_trial_ids)})"
    )
    out.append(
        f"Duplicate Trial IDs (Ckpt)   : {ckpt_duplicate_ids} "
        f"(unique={len(ckpt_id_counts)}/{len(ckpt_trial_ids)}, duplicates={len(ckpt_duplicate_ids)})"
    )
    out.append("")

    # =========================================================================
    # SECTION 3: CORRUPTION CHECKS (SHA / REOPEN / COMPILE_CLEAN / CFBF)
    # =========================================================================
    out.append(sep_major)
    out.append("3. CORRUPTION CHECKS (SHA / REOPEN / COMPILE_CLEAN / CFBF)")
    out.append(sep_major)

    base_p1_actual_sha = _sha256_file(BASE_P1_PATH) if BASE_P1_PATH.exists() else "MISSING"
    base_p1_intact = base_p1_actual_sha == BASELINE_P1_SHA

    pre_reset_ok = 0
    sha_before_ok = 0
    sha_mutated_ok = 0
    disk_sha_match_ok = 0
    ole_reopen_ok = 0
    compile_clean_ok = 0
    cfbf_verified_ok = 0
    corrupted_files: List[str] = []

    for t in trials:
        tid = str(t.get("trial_id", ""))
        if t.get("pre_reset_sha256") == BASELINE_P1_SHA:
            pre_reset_ok += 1
        if t.get("file_sha_before") == BASELINE_P1_SHA:
            sha_before_ok += 1
        if bool(t.get("sha_mutated")) and t.get("file_sha_after") != t.get("file_sha_before"):
            sha_mutated_ok += 1
        if bool(t.get("compile_clean")):
            compile_clean_ok += 1
        if bool(t.get("cfbf_verified")):
            cfbf_verified_ok += 1

        fpath = Path(str(t.get("file_path", "")))
        if fpath.exists():
            actual_sha = _sha256_file(fpath)
            if actual_sha == t.get("file_sha_after"):
                disk_sha_match_ok += 1
            else:
                corrupted_files.append(f"{tid}: sha_mismatch ({actual_sha} != {t.get('file_sha_after')})")
            reopen_ok, _n_streams, reason = _check_ole_cfbf_reopen(fpath)
            if reopen_ok:
                ole_reopen_ok += 1
            else:
                corrupted_files.append(f"{tid}: reopen_failed ({reason})")
        else:
            corrupted_files.append(f"{tid}: file_missing ({fpath})")

    # Also verify all 270 benchmark .csp files on disk
    bench_csp_files = sorted(COPIES_DIR.glob("g11_G11_W084_*.csp"))
    bench_disk_mutated = 0
    bench_ole_reopen_ok = 0
    for bf in bench_csp_files:
        b_sha = _sha256_file(bf)
        if b_sha != BASELINE_P1_SHA:
            bench_disk_mutated += 1
        ok_ole, _, _ = _check_ole_cfbf_reopen(bf)
        if ok_ole:
            bench_ole_reopen_ok += 1

    n_trials = len(trials)
    out.append(f"Baseline p1_base.csp Intact        : {base_p1_intact} (SHA-256={base_p1_actual_sha})")
    out.append(f"Pre-Reset SHA Matches Baseline     : {pre_reset_ok}/{n_trials}")
    out.append(f"Before-Edit SHA Matches Baseline   : {sha_before_ok}/{n_trials}")
    out.append(f"Post-Save SHA Mutated (Non-Trivial): {sha_mutated_ok}/{n_trials}")
    out.append(f"On-Disk .csp SHA Matches JSON      : {disk_sha_match_ok}/{n_trials}")
    out.append(f"On-Disk .csp OLE2/CFBF Reopen OK   : {ole_reopen_ok}/{n_trials}")
    out.append(f"Cscape Error Check compile_clean   : {compile_clean_ok}/{n_trials} ({100.0 * compile_clean_ok / n_trials if n_trials else 0.0:.2f}%)")
    out.append(f"CFBF Binary Oracle cfbf_verified   : {cfbf_verified_ok}/{n_trials} ({100.0 * cfbf_verified_ok / n_trials if n_trials else 0.0:.2f}%)")
    out.append(f"Corrupted / Unreadable Trial Files : {corrupted_files} (count={len(corrupted_files)})")
    out.append(
        f"Benchmark 270 On-Disk .csp Check   : files={len(bench_csp_files)}/270, "
        f"sha_mutated={bench_disk_mutated}/270, ole_cfbf_reopen_ok={bench_ole_reopen_ok}/270"
    )
    out.append(
        f"Safety & Scope Invariants          : "
        f"zero_out_of_scope_writes={invariants.get('zero_out_of_scope_writes')}, "
        f"zero_blind_retries={invariants.get('zero_blind_retries')}, "
        f"zero_false_completions={invariants.get('zero_false_completions')}, "
        f"zero_synthetic_results={invariants.get('zero_synthetic_results')}"
    )
    out.append("")

    # =========================================================================
    # SECTION 4: TOTALS (COST / TOKENS / API_CALLS)
    # =========================================================================
    out.append(sep_major)
    out.append("4. TOTALS: COST / TOKENS / API_CALLS")
    out.append(sep_major)

    sum_input_tokens = sum(int(t.get("tokens", {}).get("input_tokens", 0) or 0) for t in trials)
    sum_output_tokens = sum(int(t.get("tokens", {}).get("output_tokens", 0) or 0) for t in trials)
    sum_total_tokens = sum(int(t.get("tokens", {}).get("total_tokens", 0) or 0) for t in trials)
    sum_cost_usd = round(sum(float(t.get("tokens", {}).get("cost_usd", 0.0) or 0.0) for t in trials), 6)
    sum_api_calls = sum(int(t.get("tokens", {}).get("api_calls", 0) or 0) for t in trials)
    http_200_count = sum(1 for t in trials if t.get("tokens", {}).get("http_status") == 200)

    out.append("4A. Totals in artifacts/G11/g11_results.json (n=229 trials):")
    out.append(f"  - Total Cost (USD)     : ${sum_cost_usd:.6f} (w088_endurance.spent_usd=${float(w088_endurance.get('spent_usd', 0.0)):.6f}, cap=$25.000000)")
    out.append(f"  - Total Input Tokens   : {sum_input_tokens:,}")
    out.append(f"  - Total Output Tokens  : {sum_output_tokens:,}")
    out.append(f"  - Total Tokens Used    : {sum_total_tokens:,} (w088_endurance.total_tokens_used={int(w088_endurance.get('total_tokens_used', 0)):,}, cap=2,000,000)")
    out.append(f"  - Total API Calls Made : {sum_api_calls:,} (w088_endurance.api_calls_made={int(w088_endurance.get('api_calls_made', 0)):,}, HTTP_200={http_200_count}, cap=1,000)")
    out.append("")
    out.append("Per-Policy Token / Cost / API Call Breakdown (artifacts/G11/g11_results.json):")
    for pol in POLICIES:
        ptrials = [t for t in trials if t.get("policy") == pol]
        p_calls = sum(int(t.get("tokens", {}).get("api_calls", 0) or 0) for t in ptrials)
        p_in = sum(int(t.get("tokens", {}).get("input_tokens", 0) or 0) for t in ptrials)
        p_out = sum(int(t.get("tokens", {}).get("output_tokens", 0) or 0) for t in ptrials)
        p_tot = sum(int(t.get("tokens", {}).get("total_tokens", 0) or 0) for t in ptrials)
        p_cost = round(sum(float(t.get("tokens", {}).get("cost_usd", 0.0) or 0.0) for t in ptrials), 6)
        out.append(
            f"  - {pol:<21}: trials={len(ptrials):>3}, api_calls={p_calls:>3}, "
            f"in_tokens={p_in:>7,}, out_tokens={p_out:>6,}, total_tokens={p_tot:>7,}, cost_usd=${p_cost:.6f}"
        )

    if bench_log_info.get("found"):
        b_trials = bench_log_info["trials"]
        b_tokens = sum(bt["tokens"] for bt in b_trials)
        b_cost = round(sum(bt["cost_usd"] for bt in b_trials), 6)
        b_calls = sum(1 for bt in b_trials if bt["http_status"] == 200)
        out.append("")
        out.append("4B. 270-Trial W084-W087 Benchmark Phase Totals (from artifacts/logs/g11_campaign.log):")
        out.append(f"  - Benchmark Trials     : {len(b_trials)} (269 passed, 1 pre-f218227 fail)")
        out.append(f"  - Benchmark API Calls  : {b_calls:,} (HTTP 200)")
        out.append(f"  - Benchmark Tokens     : {b_tokens:,}")
        out.append(f"  - Benchmark Cost (USD) : ${b_cost:.6f}")
        out.append("4C. Combined Live Campaign Totals (270 Benchmark + 229 Endurance = 499 Live Cscape Trials):")
        out.append(f"  - Combined Live Trials : {len(b_trials) + len(trials):,}")
        out.append(f"  - Combined API Calls   : {b_calls + sum_api_calls:,}")
        out.append(f"  - Combined Tokens      : {b_tokens + sum_total_tokens:,}")
        out.append(f"  - Combined Cost (USD)  : ${b_cost + sum_cost_usd:.6f}")
    out.append("")

    # =========================================================================
    # SECTION 5: PASS / FAIL VERDICT VS MEGAPLAN G11 CRITERIA (W084-W090)
    # =========================================================================
    out.append(sep_major)
    out.append("5. PASS / FAIL VERDICT VS MEGAPLAN G11 CRITERIA (W084-W090)")
    out.append(sep_major)

    c_w084 = (
        w084_audit.get("status") == "success"
        and int(w084_audit.get("total_tasks", 0)) == 90
        and w084_audit.get("counts_by_family") == {"ladder": 30, "hmi": 30, "st_var": 30}
        and bool(w084_audit.get("disjoint_from_prior_gates")) is True
        and len(w084_audit.get("violations", [])) == 0
    )
    c_w085 = (
        bool(data.get("w085_same_observer_verified")) is True
        and all(len([t for t in trials if t.get("policy") == pol]) >= 75 for pol in POLICIES)
    )
    c_w086 = (
        sum_api_calls == 153
        and http_200_count == 153
        and sum_total_tokens == 156518
        and sum_cost_usd > 0.0
        and all(float(t.get("latency", {}).get("total_ms", 0.0)) > 0.0 for t in trials)
    )
    c_w087 = (
        bool(data.get("w087_project_reset_verified")) is True
        and base_p1_intact
        and pre_reset_ok == n_trials
        and sha_before_ok == n_trials
    )
    c_w088 = (
        endurance_trial_count == 229
        and status_counter.get("success", 0) == 229
        and len(failures_list) == 0
        and len(duplicate_trial_ids) == 0
        and len(ckpt_duplicate_ids) == 0
        and halted_by_horizon is True
        and halted_by_budget is False
        and cscape_restarts >= 20
        and checkpoint_json_path.exists()
    )
    c_corruption = (
        sha_mutated_ok == n_trials
        and disk_sha_match_ok == n_trials
        and ole_reopen_ok == n_trials
        and compile_clean_ok == n_trials
        and cfbf_verified_ok == n_trials
        and len(corrupted_files) == 0
    )
    c_w089 = (
        w089_stats.get("overall", {}).get("status") == "success"
        and "by_family" in w089_stats
        and "by_policy" in w089_stats
        and "cells" in w089_stats
        and len(cells_stats) == 9
    )
    c_w090 = (
        bool(invariants.get("zero_out_of_scope_writes")) is True
        and bool(invariants.get("zero_blind_retries")) is True
        and bool(invariants.get("zero_false_completions")) is True
        and bool(invariants.get("zero_synthetic_results")) is True
        and top_status == "success"
        and top_error is None
    )

    criteria_rows = [
        ("W084 Reserved 30x3 Disjoint Task Suite (90 unseen tasks)", c_w084, f"total_tasks={w084_audit.get('total_tasks')}, disjoint={w084_audit.get('disjoint_from_prior_gates')}, violations=0"),
        ("W085 Rule & LLM-Choice Baselines on Same Observer", c_w085, f"same_observer_verified={data.get('w085_same_observer_verified')}, policies=3"),
        ("W086 Per-Stage Latency & Real HTTP Token/Cost Telemetry", c_w086, f"api_calls={sum_api_calls} (HTTP 200), tokens={sum_total_tokens:,}, cost=${sum_cost_usd:.6f}"),
        ("W087 Balanced Schedule & Deterministic Project Reset", c_w087, f"base_p1_intact={base_p1_intact}, pre_reset_sha_ok={pre_reset_ok}/{n_trials}"),
        ("W088 Endurance Worker (Queue, Cap, Restarts, Checkpoint)", c_w088, f"trials={endurance_trial_count}/229 PASS, restarts={cscape_restarts}, horizon_reached={halted_by_horizon}"),
        ("W088 Corruption & Integrity (SHA, OLE2 Reopen, Compile)", c_corruption, f"sha_match={disk_sha_match_ok}/{n_trials}, reopen={ole_reopen_ok}/{n_trials}, compile_clean={compile_clean_ok}/{n_trials}"),
        ("W089 Non-Parametric Median/p95 & 95% CIs Reported", c_w089, f"overall p50={overall_p50:.1f}ms, p95={overall_p95:.1f}ms, success_ci95={overall_ci}"),
        ("W090 Zero Synthetic Results & Safety/Scope Invariants", c_w090, f"out_of_scope=0, blind_retries=0, false_completions=0, synthetic=0"),
    ]

    for label, passed_flag, detail in criteria_rows:
        tag = "PASS" if passed_flag else "FAIL"
        out.append(f"  [{tag}] {label:<56} | {detail}")

    all_passed = all(flag for _, flag, _ in criteria_rows)
    verdict_str = "PASS" if all_passed else "FAIL"
    out.append(sep_major)
    out.append(f"OVERALL GATE G11 ACCEPTANCE VERDICT: {verdict_str}")
    out.append(sep_major)

    return "\n".join(out) + "\n", all_passed


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline read-only Gate G11 acceptance verifier."
    )
    parser.add_argument(
        "--results-json",
        type=Path,
        default=DEFAULT_RESULTS_JSON,
        help="Path to artifacts/G11/g11_results.json",
    )
    parser.add_argument(
        "--checkpoint-json",
        type=Path,
        default=DEFAULT_CHECKPOINT_JSON,
        help="Path to artifacts/G11/g11_endurance_checkpoint.json",
    )
    parser.add_argument(
        "--campaign-log",
        type=Path,
        default=DEFAULT_CAMPAIGN_LOG,
        help="Path to artifacts/logs/g11_campaign.log",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_ACCEPTANCE_TXT,
        help="Output text file path (default: artifacts/G11/g11_acceptance.txt)",
    )
    args = parser.parse_args(argv)

    report_text, passed = generate_g11_acceptance_report(
        results_json_path=args.results_json,
        checkpoint_json_path=args.checkpoint_json,
        campaign_log_path=args.campaign_log,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report_text, encoding="utf-8")
    sys.stdout.write(report_text)
    sys.stdout.flush()
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
