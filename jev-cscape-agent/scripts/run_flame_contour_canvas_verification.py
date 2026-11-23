#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Flame 3D Contour & Combustion Thermal Intensity SCADA Canvas (W180).

Work Package: W180 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Status Contract: Strict 4-State JSON output & evidence emission.
"""

from __future__ import annotations

import argparse
import inspect
import json
from pathlib import Path
import sys

# Ensure repository root and src are on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root / "src") not in sys.path:
    sys.path.insert(0, str(repo_root / "src"))
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

try:
    from jev_cscape.hmi.flame_contour_canvas import run_flame_contour_canvas_verification
except ImportError as e:
    run_flame_contour_canvas_verification = None
    _import_error = e

# ANSI color escape codes
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_GREEN = "\033[92m"
CLR_RED = "\033[91m"
CLR_YELLOW = "\033[93m"
CLR_CYAN = "\033[96m"
CLR_GRAY = "\033[90m"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Run Dynamic Flame 3D Contour & Combustion Thermal Intensity Canvas (W180) 9-Stage Verification Suite."
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
        dest="output_path",
        type=str,
        default=None,
        help="Path to write JSON evidence artifact.",
    )
    parser.add_argument(
        "--svg",
        "-s",
        "--svg-path",
        dest="svg_path",
        type=str,
        default=None,
        help="Path to write SVG sample artifact.",
    )
    args = parser.parse_args()

    default_evidence = str(repo_root / "artifacts" / "HMI" / "flame_contour_canvas_evidence.json")
    default_svg = str(repo_root / "artifacts" / "HMI" / "flame_contour_canvas_sample.svg")

    evidence_file_str = args.output_path or args.positional_output or default_evidence
    svg_file_str = args.svg_path or args.positional_svg or default_svg

    evidence_path = Path(evidence_file_str)
    svg_path = Path(svg_file_str)

    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")
    print(f"  {CLR_BOLD}JEV Cscape Agent: Flame Contour Canvas Verification (W180){CLR_RESET}")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")

    if run_flame_contour_canvas_verification is None:
        print(f"  {CLR_RED}[FAIL] Unable to import run_flame_contour_canvas_verification: {_import_error}{CLR_RESET}")
        return 1

    call_kwargs = {}
    try:
        sig = inspect.signature(run_flame_contour_canvas_verification)
        for p in sig.parameters.values():
            name = p.name
            if name in ("output_path", "evidence_path", "output", "target_path"):
                call_kwargs[name] = str(evidence_path)
            elif name in ("sample_svg_path", "svg_path", "svg_export_path", "target_svg_path", "svg"):
                call_kwargs[name] = str(svg_path)
        if call_kwargs:
            report = run_flame_contour_canvas_verification(**call_kwargs)
        else:
            report = run_flame_contour_canvas_verification(output_path=str(evidence_path), sample_svg_path=str(svg_path))
    except Exception as ex:
        print(f"  {CLR_RED}[FAIL] Verification failed with exception: {ex}{CLR_RESET}")
        return 1

    # Pretty print verification stages
    data = report.get("data", {})
    tests = data.get("tests", [])

    for t in tests:
        stage = t.get("stage", "?")
        check = t.get("check", "Unknown")
        passed = t.get("passed", False)
        details = t.get("details", "")

        status_str = f"{CLR_GREEN}[PASS]{CLR_RESET}" if passed else f"{CLR_RED}[FAIL]{CLR_RESET}"
        print(f"  Stage {stage:2d}: {status_str} {check}")
        if details:
            print(f"            {CLR_GRAY}{details}{CLR_RESET}")

    passed_count = sum(1 for t in tests if t.get("passed", False))
    total_count = len(tests)

    print(f"{CLR_CYAN}{'-' * 80}{CLR_RESET}")
    print(f"  Total Checks: {passed_count}/{total_count} passing")
    print(f"  Evidence:     {evidence_path}")
    print(f"  SVG Sample:   {svg_path}")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")

    if report.get("status") == "success" and passed_count == total_count:
        print(f"  {CLR_GREEN}{CLR_BOLD}VERIFICATION SUCCESS: All stages passed deterministically.{CLR_RESET}")
        return 0
    else:
        print(f"  {CLR_RED}{CLR_BOLD}VERIFICATION FAILED: One or more checks did not pass.{CLR_RESET}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
