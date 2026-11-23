#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Sankey Process Mass & Energy Stream Flow Canvas (W159).

Work Package: W159 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
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
    from jev_cscape.hmi.sankey_canvas import run_sankey_canvas_verification
except ImportError as e:
    run_sankey_canvas_verification = None
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
        description="Run Sankey Process Mass & Energy Stream Flow Canvas (W159) 9-Stage Verification Suite."
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

    default_evidence = str(repo_root / "artifacts" / "HMI" / "sankey_canvas_evidence.json")
    default_svg = str(repo_root / "artifacts" / "HMI" / "sankey_canvas_sample.svg")

    evidence_file_str = args.output_path or args.positional_output or default_evidence
    svg_file_str = args.svg_path or args.positional_svg or default_svg

    evidence_path = Path(evidence_file_str)
    svg_path = Path(svg_file_str)

    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")
    print(f"  {CLR_BOLD}JEV Cscape Agent: Sankey Stream Flow Canvas Verification (W159){CLR_RESET}")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")

    if run_sankey_canvas_verification is None:
        print(f"  {CLR_RED}[FAIL] Unable to import run_sankey_canvas_verification: {_import_error}{CLR_RESET}")
        return 1

    try:
        sig = inspect.signature(run_sankey_canvas_verification)
        kwargs = {}
        for p in sig.parameters.values():
            name = p.name
            if name in ("evidence_path", "output_path", "output", "target_path"):
                kwargs[name] = str(evidence_path)
            elif name in ("svg_path", "sample_svg_path", "svg_export_path", "target_svg_path", "svg"):
                kwargs[name] = str(svg_path)

        if kwargs:
            evidence = run_sankey_canvas_verification(**kwargs)
        else:
            evidence = run_sankey_canvas_verification(str(evidence_path), str(svg_path))
    except TypeError:
        evidence = run_sankey_canvas_verification(str(evidence_path), str(svg_path))

    tests = evidence.get("data", {}).get("tests", [])
    for t in tests:
        stage = t.get("stage", "?")
        check = t.get("check", "Unknown")
        passed = t.get("passed", False)
        details = t.get("details", "")
        if passed:
            tag = f"{CLR_GREEN}[PASS]{CLR_RESET}"
        else:
            tag = f"{CLR_RED}[FAIL]{CLR_RESET}"
        print(f"  {CLR_BOLD}Stage {stage}{CLR_RESET}: {tag} {check}")
        if details:
            print(f"    {CLR_GRAY}-> {details}{CLR_RESET}")

    passed_count = evidence.get("data", {}).get("checks_passed", sum(1 for t in tests if t.get("passed")))
    total_count = evidence.get("data", {}).get("total_checks", len(tests))
    status = evidence.get("status", "unknown")

    print(f"{CLR_CYAN}{'-' * 80}{CLR_RESET}")
    if status == "success":
        outcome_color = CLR_GREEN
    elif status == "blocked":
        outcome_color = CLR_YELLOW
    else:
        outcome_color = CLR_RED

    print(f"[*] Outcome: {outcome_color}{passed_count}/{total_count} checks passed{CLR_RESET}.")
    print(f"[*] Status:  {outcome_color}{status.upper()}{CLR_RESET}")
    print(f"[*] Evidence artifact saved: {evidence_path.resolve()}")
    print(f"[*] SVG canvas artifact saved: {svg_path.resolve()}")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}")

    return 0 if status == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
