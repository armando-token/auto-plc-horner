#!/usr/bin/env python3
"""Verification Runner for Cscape HMI Dynamic Spatial Poisson-Disk Sampling SCADA Canvas (W288).

Work Package: W288 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Poisson-Disk Sampling SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: init_and_domain
  Stage 2: minimum_distance_constraint
  Stage 3: spatial_grid_acceleration
  Stage 4: domain_containment
  Stage 5: packing_density_metrics
  Stage 6: void_intrusion_alarm
  Stage 7: wcag_aaa_svg_rendering
  Stage 8: horner_ocs_register_sync
  Stage 9: pure_st_pou_and_ladder_rejection

Artifact Exports:
  artifacts/HMI/poisson_disk_canvas_evidence.json
  artifacts/HMI/poisson_disk_canvas_sample.svg
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Import verification entry point directly from poisson_disk_canvas
from jev_cscape.hmi.poisson_disk_canvas import (
    run_poisson_disk_canvas_verification,
)

# ANSI terminal formatting constants matching repo conventions
CLR_RESET  = "\033[0m"
CLR_BOLD   = "\033[1m"
CLR_DIM    = "\033[2m"
CLR_GREEN  = "\033[92m"
CLR_RED    = "\033[91m"
CLR_YELLOW = "\033[93m"
CLR_CYAN   = "\033[96m"
CLR_GRAY   = "\033[90m"


def format_stage_badge(passed: bool, status: Optional[str] = None) -> str:
    """Format strict 4-state contract ANSI badge."""
    norm_status = (status or "").lower()
    if norm_status == "blocked":
        return f"{CLR_YELLOW}{CLR_BOLD}[BLOCKED]{CLR_RESET}"
    if norm_status == "inconclusive":
        return f"{CLR_YELLOW}{CLR_BOLD}[INCONCLUSIVE]{CLR_RESET}"
    if passed or norm_status in ("passed", "pass", "success"):
        return f"{CLR_GREEN}{CLR_BOLD}[PASS]{CLR_RESET}"
    return f"{CLR_RED}{CLR_BOLD}[FAIL]{CLR_RESET}"


def main(argv: Optional[List[str]] = None) -> int:
    """Command-line entry point for W288 verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Run Cscape HMI Dynamic Spatial Poisson-Disk Sampling SCADA Canvas (W288) 9-Stage Verification Suite"
    )
    parser.add_argument(
        "positional_output",
        nargs="?",
        default=None,
        help="Optional positional path to write JSON evidence artifact.",
    )
    parser.add_argument(
        "positional_svg",
        nargs="?",
        default=None,
        help="Optional positional path to write SVG sample artifact.",
    )
    parser.add_argument(
        "--output",
        "-o",
        "--evidence-path",
        "-e",
        "--evidence",
        dest="output_path",
        type=str,
        default=None,
        help="Path to output verification evidence JSON",
    )
    parser.add_argument(
        "--svg",
        "-s",
        "--svg-path",
        "--sample-svg",
        dest="svg_path",
        type=str,
        default=None,
        help="Path to output standalone SVG sample",
    )
    parser.add_argument(
        "--work-package",
        type=str,
        default="W288",
        help="Work package identifier (default: W288)",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Emit raw JSON report only (no ANSI stdout banner)",
    )
    args = parser.parse_args(argv)

    default_evidence = str(REPO_ROOT / "artifacts" / "HMI" / "poisson_disk_canvas_evidence.json")
    default_svg = str(REPO_ROOT / "artifacts" / "HMI" / "poisson_disk_canvas_sample.svg")

    evidence_file_str = args.output_path or args.positional_output or default_evidence
    svg_file_str = args.svg_path or args.positional_svg or default_svg

    evidence_path = Path(evidence_file_str)
    svg_path = Path(svg_file_str)

    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json_only:
        print(f"\n{CLR_CYAN}{'=' * 80}{CLR_RESET}")
        print(f"  {CLR_BOLD}JEV Cscape Agent: Poisson-Disk Sampling Canvas Verification ({args.work_package}){CLR_RESET}")
        print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")

    start_time = time.perf_counter()
    report = run_poisson_disk_canvas_verification(
        output_path=str(evidence_path),
        sample_svg_path=str(svg_path),
        work_package=args.work_package,
    )
    elapsed_total_ms = (time.perf_counter() - start_time) * 1000.0

    if args.json_only:
        print(json.dumps(report, indent=2))
        return 0 if report.get("status") == "success" else 1

    data = report.get("data", {})
    tests = data.get("tests", data.get("stages", []))

    for t in tests:
        stage = t.get("stage", "?")
        check = t.get("name") or t.get("check", "Unknown")
        passed = t.get("passed", False)
        status = t.get("status", None)
        details = t.get("details", "")

        dur_ms = t.get("timing_ms") or t.get("duration_ms")
        timing_str = f"[{dur_ms:.2f}ms]" if dur_ms is not None else ""

        badge = format_stage_badge(passed, status)
        if isinstance(stage, int):
            print(f"  Stage {stage:2d}: {badge} {timing_str:<10} {check}")
        else:
            print(f"  Stage {stage}: {badge} {timing_str:<10} {check}")

        if details:
            print(f"            {CLR_GRAY}-> {details}{CLR_RESET}")

    passed_count = sum(1 for t in tests if t.get("passed", False))
    total_count = len(tests)

    print(f"{CLR_CYAN}{'-' * 80}{CLR_RESET}")
    print(f"  Total Checks: {passed_count}/{total_count} passing (in {elapsed_total_ms:.2f} ms)")
    print(f"  Evidence:     {evidence_path.resolve()}")
    print(f"  SVG Sample:   {svg_path.resolve()}")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")

    status = report.get("status", "unknown")
    if status == "success" and passed_count == total_count and total_count >= 9:
        print(f"  {CLR_GREEN}{CLR_BOLD}VERIFICATION SUCCESS: All 9 stages passed deterministically.{CLR_RESET}\n")
        return 0
    else:
        print(f"  {CLR_RED}{CLR_BOLD}VERIFICATION FAILED: One or more checks did not pass (status={status}).{CLR_RESET}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
