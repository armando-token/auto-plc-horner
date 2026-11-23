#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Spatial Convex Hull Boundary SCADA Canvas (W276).

Work Package: W276 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Convex Hull Boundary SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: Initialization & Spatial Node Configuration
  Stage 2: Pure ST POU Validation
  Stage 3: Ladder Logic Rejection Guard
  Stage 4: Convex Hull Algorithmic Correctness
  Stage 5: Geometric Metrics (Area, Perimeter, Centroid, Radius)
  Stage 6: Boundary Breach & Dispersion Alarm Detection
  Stage 7: High-Contrast WCAG 2.1 AAA SVG 1.1 Render
  Stage 8: RegisterTable Synchronization (%R2370..%R2377, %M553..%M554)
  Stage 9: Deterministic Multi-Cycle Closed-Loop Scan

Exports:
  artifacts/HMI/convex_hull_canvas_evidence.json
  artifacts/HMI/convex_hull_canvas_sample.svg
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

# Import verification entry point directly from convex_hull_canvas
from jev_cscape.hmi.convex_hull_canvas import (
    run_convex_hull_canvas_verification,
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
    """Command-line entry point for W276 verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Run Cscape HMI Dynamic Spatial Convex Hull Boundary 9-Stage Verification Suite (W276)"
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
        default="W276",
        help="Work package identifier (default: W276)",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Emit raw JSON report only (no ANSI stdout banner)",
    )
    args = parser.parse_args(argv)

    default_evidence = str(REPO_ROOT / "artifacts" / "HMI" / "convex_hull_canvas_evidence.json")
    default_svg = str(REPO_ROOT / "artifacts" / "HMI" / "convex_hull_canvas_sample.svg")

    evidence_file_str = args.output_path or args.positional_output or default_evidence
    svg_file_str = args.svg_path or args.positional_svg or default_svg

    evidence_path = Path(evidence_file_str)
    svg_path = Path(svg_file_str)

    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json_only:
        print(f"\n{CLR_CYAN}{'=' * 80}{CLR_RESET}")
        print(f"  {CLR_BOLD}JEV Cscape Agent: Convex Hull Canvas Verification (W276){CLR_RESET}")
        print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")

    start_time = time.perf_counter()
    report = run_convex_hull_canvas_verification(
        evidence_path=str(evidence_path),
        svg_export_path=str(svg_path),
        output_path=str(evidence_path),
        sample_svg_path=str(svg_path),
        svg_path=str(svg_path),
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
        check = t.get("check", "Unknown")
        passed = t.get("passed", False)
        details = t.get("details", "")

        dur_ms = t.get("duration_ms")
        timing_str = f"[{dur_ms:.2f}ms]" if dur_ms is not None else ""

        badge = format_stage_badge(passed)
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
