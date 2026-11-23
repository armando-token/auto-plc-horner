#!/usr/bin/env python3
"""Verification Script for Industrial SERCOS III Real-Time Ethernet & Optical Fiber Ring Redundancy Engine (W145).

Work Package: W145 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/telemetry/sercos3_ring_evidence.json
"""

from __future__ import annotations

import argparse
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="JEV Cscape Agent: Industrial SERCOS III Ring Redundancy Verification (W145)"
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
    args = parser.parse_args()

    # Determine evidence target path (flag > positional > default)
    selected_path = args.flag_path or args.positional_path
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "sercos3_ring_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print(f"  {ESC_BOLD}JEV Cscape Agent: Industrial SERCOS III Ring Redundancy Verification (W145){ESC_RESET}")
    print("=" * 80)

    try:
        from jev_cscape.telemetry.sercos3_ring import run_sercos3_ring_verification
    except ImportError as exc:
        print(f"\n[{ESC_RED}{ESC_BOLD}ERROR{ESC_RESET}] Failed to import `run_sercos3_ring_verification`:")
        print(f"  {exc}")
        print("=" * 80)
        return 1

    try:
        try:
            evidence = run_sercos3_ring_verification(evidence_path=str(evidence_path))
        except TypeError:
            evidence = run_sercos3_ring_verification(output_path=str(evidence_path))
    except TypeError:
        evidence = run_sercos3_ring_verification(str(evidence_path))
    except Exception as exc:
        print(f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:")
        print(f"  {type(exc).__name__}: {exc}")
        print("=" * 80)
        return 1

    # Extract stages and checks
    tests = evidence.get("data", {}).get("tests", [])
    for t in tests:
        stage_num = t.get("stage", "?")
        check_name = t.get("check", "unnamed_check")
        passed = t.get("passed", False)
        details = t.get("details", "")
        print(format_stage_result(stage_num, check_name, passed, details))

    passed_count = evidence.get("data", {}).get("checks_passed", sum(1 for t in tests if t.get("passed", False)))
    total_count = evidence.get("data", {}).get("total_checks", len(tests))
    status_str = evidence.get("status", "unknown")

    print("-" * 80)
    status_badge = f"{ESC_GREEN}{ESC_BOLD}{status_str.upper()}{ESC_RESET}" if status_str == "success" else f"{ESC_RED}{ESC_BOLD}{status_str.upper()}{ESC_RESET}"
    print(f"[*] Outcome: {passed_count}/{total_count} checks passed across {len(tests)} verification stages.")
    print(f"[*] Status: {status_badge}")
    print(f"[*] Evidence artifact saved: {ESC_CYAN}{evidence_path}{ESC_RESET}")
    print("=" * 80)

    return 0 if status_str == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
