#!/usr/bin/env python3
"""Gate G3 Real Program Variables Edit Roundtrip Campaign Runner.

Executes 10 sequential roundtrips on fresh disposable copies of p1_base.csp,
rotating through values G3_TEST_VAR_01, G3_TEST_VAR_02, G3_TEST_VAR_03.
Generates:
  1. Exactly one PASS/FAIL line printed per run:
     [RUN 01/10] PASS | Value: G3_TEST_VAR_01 | Initial SHA: <sha> | Saved SHA: <sha> | Reopen SHA: <sha> | Reopen Decl Count: 24
  2. One consolidated summary JSON at artifacts/G3/g3_campaign_summary.json
  3. Stops immediately on first FAIL (fail-closed discipline).

Safety Invariants:
  - NEVER modifies or saves work/disposable/p1_base.csp or work/disposable/test_sandbox.csp
  - Fail-closed COM port and download command lockout enforced via assert_safety_invariants()
"""

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional

# Ensure repository root is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.g3_edit_roundtrip import (
    run_edit_roundtrip,
    assert_safety_invariants,
    close_cscape_gracefully,
    kill_leftover_cscape,
    compute_sha256,
    BASE_P1_PATH,
    COPIES_DIR,
    EVIDENCE_PATH,
    BASELINE_P1_SHA,
    BASELINE_SANDBOX_SHA,
)

# Campaign configuration
CAMPAIGN_SUMMARY_PATH = REPO_ROOT / "artifacts" / "G3" / "g3_campaign_summary.json"
CAMPAIGN_RUNS_DIR = REPO_ROOT / "artifacts" / "G3" / "campaign_runs"
LOG_DIR = REPO_ROOT / "artifacts" / "logs"

ROTATING_VALUES = ["G3_TEST_VAR_01", "G3_TEST_VAR_02", "G3_TEST_VAR_03"]
DEFAULT_TOTAL_RUNS = 10
REQUIRED_REOPEN_DECL_COUNT = 24

# Setup logger for campaign
LOG_DIR.mkdir(parents=True, exist_ok=True)
campaign_log_path = LOG_DIR / "g3_campaign.log"
logger = logging.getLogger("g3_campaign")
logger.setLevel(logging.INFO)

# Formatter and file handler
file_handler = logging.FileHandler(campaign_log_path, mode="w", encoding="utf-8")
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(file_handler)


def run_campaign(
    total_runs: int = DEFAULT_TOTAL_RUNS,
    summary_path: Optional[Path] = None,
    stop_on_fail: bool = True
) -> int:
    """Run sequential roundtrip campaign.

    Args:
        total_runs: Number of sequential roundtrips to execute (default: 10).
        summary_path: Path to output consolidated summary JSON.
        stop_on_fail: Stop immediately on first failed run (default: True).

    Returns:
        0 if all runs passed, 1 if any run failed.
    """
    out_summary_path = summary_path or CAMPAIGN_SUMMARY_PATH
    out_summary_path.parent.mkdir(parents=True, exist_ok=True)
    CAMPAIGN_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    COPIES_DIR.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 90)
    print(f"  STARTING GATE G3 EDIT ROUNDTRIP CAMPAIGN: {total_runs} SEQUENTIAL RUNS")
    print(f"  Rotating Values:       {', '.join(ROTATING_VALUES)}")
    print(f"  Summary JSON Target:   {out_summary_path}")
    print(f"  Stop on First FAIL:    {stop_on_fail}")
    print("=" * 90 + "\n")

    logger.info(f"Starting G3 roundtrip campaign: {total_runs} runs planned.")

    # Pre-campaign: kill leftover Cscape and assert safety invariants
    kill_leftover_cscape()
    assert_safety_invariants()

    campaign_summary: Dict[str, Any] = {
        "campaign_task": "G3_PROGRAM_VARIABLES_10_RUN_CAMPAIGN",
        "timestamp_start_utc": datetime.now(timezone.utc).isoformat(),
        "timestamp_end_utc": None,
        "total_planned_runs": total_runs,
        "runs_executed": 0,
        "runs_passed": 0,
        "runs_failed": 0,
        "overall_status": "inconclusive",
        "rotating_values": ROTATING_VALUES,
        "baseline_p1_sha256": BASELINE_P1_SHA,
        "baseline_sandbox_sha256": BASELINE_SANDBOX_SHA,
        "required_reopen_decl_count": REQUIRED_REOPEN_DECL_COUNT,
        "runs": [],
    }

    all_passed = True

    for i in range(total_runs):
        run_number = i + 1
        var_name = ROTATING_VALUES[i % len(ROTATING_VALUES)]
        copy_filename = f"campaign_run_{run_number:02d}.csp"
        copy_path = COPIES_DIR / copy_filename
        run_evidence_path = CAMPAIGN_RUNS_DIR / f"run_{run_number:02d}_evidence.json"

        # Ensure target copy does not exist prior to run (guarantee fresh copy of p1_base.csp)
        if copy_path.exists():
            try:
                copy_path.unlink()
            except Exception as e:
                logger.warning(f"Could not delete existing copy {copy_path}: {e}")

        # Kill leftover Cscape before each run per user directive
        kill_leftover_cscape()
        time.sleep(1.0)

        logger.info(f"--- Launching Campaign Run {run_number:02d}/{total_runs:02d} (Var: {var_name}) ---")

        run_exit_code = 1
        run_evidence: Dict[str, Any] = {}

        try:
            run_exit_code = run_edit_roundtrip(
                new_var_name=var_name,
                target_copy_path=copy_path,
                evidence_path=run_evidence_path
            )
        except Exception as e:
            logger.error(f"Run {run_number:02d} raised unhandled exception: {e}", exc_info=True)
            run_exit_code = 1

        # Load run evidence JSON if written
        if run_evidence_path.exists():
            try:
                with open(run_evidence_path, "r", encoding="utf-8") as f:
                    run_evidence = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to read {run_evidence_path}: {e}")
        elif EVIDENCE_PATH.exists():
            try:
                with open(EVIDENCE_PATH, "r", encoding="utf-8") as f:
                    run_evidence = json.load(f)
            except Exception:
                pass

        # Extract run metrics
        init_sha = run_evidence.get("initial_sha256") or "UNKNOWN"
        saved_sha = run_evidence.get("saved_sha256") or "UNKNOWN"
        reopen_sha = run_evidence.get("reopened_sha256") or "UNKNOWN"
        reopen_decl_count = run_evidence.get("reopen_decl_count")
        if reopen_decl_count is None or reopen_decl_count == "":
            reopen_decl_count = "READ_ERROR"
        sha_changed = run_evidence.get("sha_changed", False)
        sha_preserved = run_evidence.get("sha_preserved_on_reopen", False)
        var_persisted = run_evidence.get("variable_persisted", False)
        error_msg = run_evidence.get("error")

        # Evaluate pass criteria: exit code 0, status == 'success', sha_changed, sha_preserved, reopen_decl_count == 24
        run_passed = (
            run_exit_code == 0
            and run_evidence.get("status") == "success"
            and sha_changed is True
            and sha_preserved is True
            and reopen_decl_count == REQUIRED_REOPEN_DECL_COUNT
        )

        status_str = "PASS" if run_passed else "FAIL"

        # PRINT EXACT REQUIRED ONE-LINE PASS/FAIL STATUS PER USER DIRECTIVE:
        # (value, initial/saved/reopen SHA, reopen decl count)
        line = (
            f"[RUN {run_number:02d}/{total_runs:02d}] {status_str} | "
            f"Value: {var_name} | "
            f"Initial SHA: {init_sha} | "
            f"Saved SHA: {saved_sha} | "
            f"Reopen SHA: {reopen_sha} | "
            f"Reopen Decl Count: {reopen_decl_count}"
        )
        if not run_passed and error_msg:
            line += f" | Error: {error_msg}"
        print(line)
        logger.info(line)

        # Record run in summary
        run_summary_entry = {
            "run_number": run_number,
            "status": status_str,
            "value": var_name,
            "copy_path": str(copy_path),
            "initial_sha256": init_sha,
            "saved_sha256": saved_sha,
            "reopened_sha256": reopen_sha,
            "sha_changed": sha_changed,
            "sha_preserved_on_reopen": sha_preserved,
            "reopen_decl_count": reopen_decl_count,
            "required_reopen_decl_count": REQUIRED_REOPEN_DECL_COUNT,
            "exit_code": run_exit_code,
            "error": error_msg,
            "evidence_file": str(run_evidence_path),
        }
        campaign_summary["runs"].append(run_summary_entry)
        campaign_summary["runs_executed"] += 1

        if run_passed:
            campaign_summary["runs_passed"] += 1
        else:
            campaign_summary["runs_failed"] += 1
            all_passed = False

            # Stop on first FAIL per user directive
            if stop_on_fail:
                print(f"\n[CAMPAIGN ABORTED] Run {run_number:02d} FAILED. Stopping on first FAIL per user directive.\n")
                logger.error(f"Campaign stopped on first fail at run {run_number:02d}.")
                break

    # Post-campaign: kill leftover Cscape and assert safety invariants
    kill_leftover_cscape()
    assert_safety_invariants()

    campaign_summary["timestamp_end_utc"] = datetime.now(timezone.utc).isoformat()
    campaign_summary["overall_status"] = "success" if (all_passed and campaign_summary["runs_executed"] == total_runs) else "failed"

    # Save consolidated summary JSON
    with open(out_summary_path, "w", encoding="utf-8") as f:
        json.dump(campaign_summary, f, indent=2)
    logger.info(f"Campaign summary JSON written to: {out_summary_path}")

    print("\n" + "=" * 90)
    print(f"  CAMPAIGN COMPLETE: Overall Status = {campaign_summary['overall_status'].upper()}")
    print(f"  Runs Planned:     {total_runs}")
    print(f"  Runs Executed:    {campaign_summary['runs_executed']}")
    print(f"  Runs Passed:      {campaign_summary['runs_passed']}")
    print(f"  Runs Failed:      {campaign_summary['runs_failed']}")
    print(f"  Summary JSON:     {out_summary_path}")
    print("=" * 90 + "\n")

    return 0 if campaign_summary["overall_status"] == "success" else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Gate G3 10-Run Sequential Program Variables Edit Roundtrip Campaign"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_TOTAL_RUNS,
        help=f"Total sequential runs (default: {DEFAULT_TOTAL_RUNS})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path for summary JSON (default: artifacts/G3/g3_campaign_summary.json)",
    )
    parser.add_argument(
        "--no-stop-on-fail",
        action="store_true",
        default=False,
        help="Do not stop on first fail (continue all runs)",
    )
    args = parser.parse_args()

    return run_campaign(
        total_runs=args.count,
        summary_path=args.output,
        stop_on_fail=not args.no_stop_on_fail,
    )


if __name__ == "__main__":
    sys.exit(main())
