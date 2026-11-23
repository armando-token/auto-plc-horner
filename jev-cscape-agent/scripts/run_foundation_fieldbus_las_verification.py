#!/usr/bin/env python3
"""Verification Script for Industrial FOUNDATION Fieldbus H1 Link Active Scheduler (LAS) & Function Block Bridge Engine (W181).

Work Package: W181 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/telemetry/foundation_fieldbus_las_evidence.json
"""

from __future__ import annotations

import argparse
import inspect
import json
from pathlib import Path
import sys
from typing import Any, Dict

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# ANSI terminal formatting constants matching repo conventions
ESC_RESET = "\033[0m"
ESC_BOLD = "\033[1m"
ESC_DIM = "\033[2m"
ESC_GREEN = "\033[92m"
ESC_RED = "\033[91m"
ESC_YELLOW = "\033[93m"
ESC_CYAN = "\033[96m"


def format_stage_result(stage: int | str, check: str, passed: bool, details: str = "") -> str:
    """Format a single stage line with ANSI colored badge and description."""
    if passed:
        badge = f"{ESC_GREEN}{ESC_BOLD}PASS{ESC_RESET}"
    else:
        badge = f"{ESC_RED}{ESC_BOLD}FAIL{ESC_RESET}"
    line = f"  Stage {stage}: [{badge}] {check}"
    if details:
        line += f"\n    {ESC_DIM}{details}{ESC_RESET}"
    return line


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="JEV Cscape Agent: Industrial FOUNDATION Fieldbus H1 LAS Bridge Engine Verification (W181)"
    )
    parser.add_argument(
        "positional_path",
        nargs="?",
        default=None,
        help="Optional positional path for output evidence JSON file",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="flag_path",
        default=None,
        help="Specified evidence JSON output path",
    )
    args = parser.parse_args(argv)

    selected_path = args.flag_path or args.positional_path
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "foundation_fieldbus_las_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print(f"  {ESC_BOLD}JEV Cscape Agent: Industrial FOUNDATION Fieldbus H1 LAS Bridge Engine Verification (W181){ESC_RESET}")
    print("=" * 80)

    try:
        from jev_cscape.telemetry.foundation_fieldbus_las import run_foundation_fieldbus_las_verification
    except ImportError as exc:
        print(f"\n[{ESC_RED}{ESC_BOLD}ERROR{ESC_RESET}] Failed to import `run_foundation_fieldbus_las_verification`:")
        print(f"  {exc}")
        print("=" * 80)
        return 1

    try:
        sig = inspect.signature(run_foundation_fieldbus_las_verification)
        if "output_path" in sig.parameters:
            evidence = run_foundation_fieldbus_las_verification(output_path=str(evidence_path))
        elif "evidence_path" in sig.parameters:
            evidence = run_foundation_fieldbus_las_verification(evidence_path=str(evidence_path))
        else:
            evidence = run_foundation_fieldbus_las_verification(str(evidence_path))
    except Exception as exc:
        print(f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:")
        print(f"  {type(exc).__name__}: {exc}")
        print("=" * 80)
        return 1

    tests = evidence.get("data", {}).get("tests", [])
    for t in tests:
        stage_num = t.get("stage", "?")
        check_name = t.get("check", "Unknown")
        passed = t.get("passed", False)
        details = t.get("details", "")
        print(format_stage_result(stage_num, check_name, passed, details))

    overall_status = evidence.get("status")
    checks_passed = evidence.get("data", {}).get("checks_passed", 0)
    total_checks = evidence.get("data", {}).get("total_checks", 0)

    print("-" * 80)
    print(f"  Result: {checks_passed}/{total_checks} stages passed. Status: {overall_status.upper() if overall_status else 'UNKNOWN'}")
    print(f"  Evidence: {evidence_path}")
    print("=" * 80)

    return 0 if overall_status == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
