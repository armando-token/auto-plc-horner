#!/usr/bin/env python3
"""Verification Script for Industrial Caprolactam Beckmann Fluidized Bed ODE Simulation (W239).

Work Package: W239 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Rigorous Process Physics & Numerical Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/simulation/caprolactam_fluidized_bed_evidence.json
"""

from __future__ import annotations

import argparse
import json
import os
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

try:
    from jev_cscape.simulation.caprolactam_fluidized_bed import (
        run_caprolactam_fluidized_bed_verification,
    )
    _import_error = None
except ImportError as exc:
    try:
        from jev_cscape.simulation import run_caprolactam_fluidized_bed_verification
        _import_error = None
    except ImportError:
        run_caprolactam_fluidized_bed_verification = None
        _import_error = exc

# ANSI terminal formatting constants matching repo conventions
ESC_RESET = "\033[0m"
ESC_BOLD = "\033[1m"
ESC_DIM = "\033[2m"
ESC_GREEN = "\033[92m"
ESC_RED = "\033[91m"
ESC_YELLOW = "\033[93m"
ESC_CYAN = "\033[96m"


def format_stage_result(
    stage: int | str,
    check: str,
    passed: bool,
    timing_ms: Optional[float] = None,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format single stage verification outcome for terminal display."""
    if status is not None:
        if status == "success":
            badge = f"{ESC_GREEN}[PASS]{ESC_RESET}"
        elif status == "blocked":
            badge = f"{ESC_YELLOW}[BLOCKED]{ESC_RESET}"
        else:
            badge = f"{ESC_RED}[FAIL]{ESC_RESET}"
    else:
        badge = f"{ESC_GREEN}[PASS]{ESC_RESET}" if passed else f"{ESC_RED}[FAIL]{ESC_RESET}"

    timing_str = f" ({timing_ms:.1f}ms)" if timing_ms is not None else ""
    line = f"  Stage {stage:>2}: {badge} {ESC_BOLD}{check}{ESC_RESET}{timing_str}"
    if details:
        line += f"\n            {ESC_DIM}{details}{ESC_RESET}"
    return line


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute W239 Caprolactam Fluidized Bed Rearrangement 9-Stage Verification Suite."
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=str(REPO_ROOT / "artifacts" / "simulation" / "caprolactam_fluidized_bed_evidence.json"),
        help="Path to output verification JSON evidence artifact.",
    )
    parser.add_argument(
        "--work-package",
        type=str,
        default="W239",
        help="Work package identifier (default: W239).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON directly to stdout.",
    )
    args = parser.parse_args()

    if _import_error is not None or run_caprolactam_fluidized_bed_verification is None:
        payload = {
            "status": "failed",
            "error_code": "IMPORT_ERROR",
            "details": f"Failed to import run_caprolactam_fluidized_bed_verification: {_import_error}",
            "data": {"work_package": args.work_package},
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"{ESC_RED}ERROR: Failed to import verification suite: {_import_error}{ESC_RESET}")
        return 1

    t0 = time.time()
    out_path = Path(args.output).resolve()
    result = run_caprolactam_fluidized_bed_verification(output_path=out_path, work_package=args.work_package)
    elapsed_total_ms = (time.time() - t0) * 1000.0

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result.get("status") == "success" else 1

    print("\n" + "=" * 72)
    print(f"  {args.work_package} CAPROLACTAM FLUIDIZED BED REARRANGEMENT 9-STAGE VERIFICATION SUITE")
    print("=" * 72 + "\n")

    tests = result.get("data", {}).get("stages") or result.get("data", {}).get("tests", [])
    for t in tests:
        st_num = t.get("stage", "?")
        check_name = t.get("name", t.get("check", "Stage Check"))
        passed = t.get("passed", False)
        details = t.get("details", "")
        print(format_stage_result(st_num, check_name, passed, details=details))

    overall_status = result.get("status", "failed")
    passed_count = result.get("data", {}).get("checks_passed", 0)
    total_count = result.get("data", {}).get("total_checks", len(tests))

    print("\n" + "-" * 72)
    if overall_status == "success":
        print(
            f"  RESULT: {ESC_GREEN}{ESC_BOLD}SUCCESS{ESC_RESET} "
            f"({passed_count}/{total_count} checks passed in {elapsed_total_ms:.1f}ms)"
        )
    else:
        print(
            f"  RESULT: {ESC_RED}{ESC_BOLD}FAILED{ESC_RESET} "
            f"({passed_count}/{total_count} checks passed in {elapsed_total_ms:.1f}ms)"
        )
    print(f"  Evidence written to: {out_path}\n")

    return 0 if overall_status == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
