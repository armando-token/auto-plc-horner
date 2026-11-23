#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Spatial Alpha Shape SCADA Canvas (W279).

Work Package: W279 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Alpha Shape Non-Convex Concave Boundary SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: Initialization & Spatial Node Configuration
  Stage 2: Pure ST POU Validation
  Stage 3: Ladder Logic Rejection Guard
  Stage 4: Alpha Shape Algorithmic Correctness
  Stage 5: Geometric Metrics (Area, Perimeter, Concavity Index)
  Stage 6: Boundary Breach & High Concavity Alarm Detection
  Stage 7: High-Contrast WCAG 2.1 AAA SVG 1.1 Render
  Stage 8: RegisterTable Synchronization (%R2400..%R2407, %M560..%M561)
  Stage 9: Deterministic Multi-Cycle Closed-Loop Scan

Exports:
  artifacts/HMI/alpha_shape_canvas_evidence.json
  artifacts/HMI/alpha_shape_canvas_sample.svg
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

from jev_cscape.hmi.alpha_shape_canvas import (
    run_alpha_shape_canvas_verification,
)

# ANSI terminal formatting constants
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
    """Command-line entry point for W279 verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Run Cscape HMI Dynamic Spatial Alpha Shape Boundary 9-Stage Verification Suite (W279)"
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
        "--sample-svg-path",
        dest="sample_svg_path",
        type=str,
        default=None,
        help="Path to output sample SVG 1.1 vector graphic artifact",
    )
    parser.add_argument(
        "--work-package",
        "-w",
        dest="work_package",
        type=str,
        default="W279",
        help="Work package code (default: W279)",
    )

    args = parser.parse_args(argv)

    default_output_dir = REPO_ROOT / "artifacts" / "HMI"
    default_output_dir.mkdir(parents=True, exist_ok=True)

    evidence_file = (
        args.output_path
        or args.positional_output
        or str(default_output_dir / "alpha_shape_canvas_evidence.json")
    )
    svg_file = (
        args.sample_svg_path
        or args.positional_svg
        or str(default_output_dir / "alpha_shape_canvas_sample.svg")
    )

    print(f"\n{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_CYAN} Cscape HMI Dynamic Spatial Alpha Shape Canvas Verification (W279){CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}")
    print(f" Evidence Destination : {evidence_file}")
    print(f" SVG Artifact Output  : {svg_file}")
    print(f" Target Work Package  : {args.work_package}")
    print(f"{CLR_DIM}----------------------------------------------------------------------{CLR_RESET}\n")

    t_start = time.perf_counter()
    res = run_alpha_shape_canvas_verification(
        output_path=evidence_file,
        sample_svg_path=svg_file,
        work_package=args.work_package,
    )
    t_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    tests = res.get("data", {}).get("tests", [])
    for t in tests:
        stg = t.get("stage", 0)
        chk = t.get("check", "Unknown")
        p = t.get("passed", False)
        dur = t.get("duration_ms", 0.0)
        det = t.get("details", "")
        badge = format_stage_badge(p)
        print(f" Stage {stg:02d}: {chk:<46} {badge} {CLR_DIM}({dur:>5.1f} ms){CLR_RESET}")
        if det:
            print(f"          {CLR_GRAY}└─ {det}{CLR_RESET}")

    total_checks = res.get("data", {}).get("total_checks", len(tests))
    passed_checks = res.get("data", {}).get("checks_passed", 0)
    status_str = res.get("status", "failed")

    print(f"\n{CLR_DIM}----------------------------------------------------------------------{CLR_RESET}")
    if status_str == "success":
        print(f" {CLR_GREEN}{CLR_BOLD}RESULT: SUCCESS ({passed_checks}/{total_checks} checks passed in {t_elapsed_ms:.1f} ms){CLR_RESET}")
    else:
        print(f" {CLR_RED}{CLR_BOLD}RESULT: FAILED ({passed_checks}/{total_checks} checks passed in {t_elapsed_ms:.1f} ms){CLR_RESET}")
    print(f"{CLR_BOLD}{CLR_CYAN}======================================================================{CLR_RESET}\n")

    return 0 if status_str == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
