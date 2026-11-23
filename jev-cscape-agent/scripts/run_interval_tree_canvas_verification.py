#!/usr/bin/env python3
"""Verification Runner for Cscape HMI Dynamic Spatial Interval Tree SCADA Canvas (W300).

Work Package: W300 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Interval Tree SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: environment
  Stage 2: interval_structures
  Stage 3: range_queries
  Stage 4: spatial_2d_projection
  Stage 5: svg_rendering_and_wcag
  Stage 6: register_synchronization
  Stage 7: structured_text_validation
  Stage 8: scan_cycle_simulation
  Stage 9: evidence_emission

Artifact Exports:
  artifacts/HMI/interval_tree_canvas_evidence.json
  artifacts/HMI/interval_tree_canvas_sample.svg
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

# Import verification entry point directly from interval_tree_canvas
from jev_cscape.hmi.interval_tree_canvas import (
    run_interval_tree_canvas_verification,
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
    """Command-line entry point for W300 verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Run Cscape HMI Dynamic Spatial Interval Tree SCADA Canvas (W300) 9-Stage Verification Suite"
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
        default="artifacts/HMI/interval_tree_canvas_evidence.json",
        help="Path to output verification evidence JSON (default: artifacts/HMI/interval_tree_canvas_evidence.json)",
    )
    parser.add_argument(
        "--svg-output",
        "--svg",
        "-s",
        "--svg-path",
        "--sample-svg",
        dest="svg_output",
        type=str,
        default="artifacts/HMI/interval_tree_canvas_sample.svg",
        help="Path to output standalone SVG sample (default: artifacts/HMI/interval_tree_canvas_sample.svg)",
    )
    parser.add_argument(
        "--quick",
        "-q",
        action="store_true",
        help="Execute accelerated verification with reduced simulation cycles",
    )
    parser.add_argument(
        "--work-package",
        type=str,
        default="W300",
        help="Work package identifier (default: W300)",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Emit raw JSON report only (no ANSI stdout banner)",
    )
    args = parser.parse_args(argv)

    evidence_file_str = args.positional_output or args.output_path
    svg_file_str = args.positional_svg or args.svg_output

    evidence_path = Path(evidence_file_str)
    svg_path = Path(svg_file_str)

    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json_only:
        print(f"\n{CLR_CYAN}{'=' * 80}{CLR_RESET}")
        print(f"  {CLR_BOLD}JEV Cscape Agent: Spatial Interval Tree Canvas Verification ({args.work_package}){CLR_RESET}")
        print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")

    t_start = time.perf_counter()
    report = run_interval_tree_canvas_verification(
        output_path=str(evidence_path),
        sample_svg_path=str(svg_path),
        work_package=args.work_package,
        quick=args.quick,
    )
    elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    stages = report.get("data", {}).get("stages", [])
    passed_count = report.get("data", {}).get("checks_passed", 0)
    total_count = report.get("data", {}).get("total_checks", len(stages))
    all_passed = (report.get("status") == "success" and passed_count == total_count and total_count >= 9)

    if not args.json_only:
        for s in stages:
            idx = s.get("stage", 0)
            name = s.get("name", "stage")
            passed = s.get("passed", False)
            timing = s.get("timing_ms", 0.0)
            details = s.get("details", "")
            badge = format_stage_badge(passed)
            print(f"  {badge} Stage {idx:02d}: {CLR_BOLD}{name:<32}{CLR_RESET} ({timing:6.2f} ms) - {details}")

        print(f"{CLR_CYAN}{'-' * 80}{CLR_RESET}")
        status_badge = (
            f"{CLR_GREEN}{CLR_BOLD}[VERIFIED SUCCESS]{CLR_RESET}"
            if all_passed
            else f"{CLR_RED}{CLR_BOLD}[VERIFICATION FAILED]{CLR_RESET}"
        )
        print(f"  Result: {status_badge}  Passed: {passed_count}/{total_count}  Elapsed: {elapsed_ms:.2f} ms")
        print(f"  Evidence: {CLR_DIM}{evidence_path.resolve()}{CLR_RESET}")
        print(f"  Sample:   {CLR_DIM}{svg_path.resolve()}{CLR_RESET}")
        print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}\n")
    else:
        print(json.dumps(report, indent=2))

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
