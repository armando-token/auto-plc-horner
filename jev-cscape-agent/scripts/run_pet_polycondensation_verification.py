#!/usr/bin/env python3
"""Verification Script for Industrial PET Polycondensation ODE Simulation (W236).

Work Package: W236 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Rigorous Process Physics & Numerical Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/simulation/pet_polycondensation_evidence.json
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
    from jev_cscape.simulation.pet_polycondensation import (
        run_pet_polycondensation_verification,
    )
    _import_error = None
except ImportError as exc:
    try:
        from jev_cscape.simulation import run_pet_polycondensation_verification
        _import_error = None
    except ImportError:
        run_pet_polycondensation_verification = None
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
        description="Execute W236 PET Polycondensation Reactor 9-Stage Verification Suite."
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=str(REPO_ROOT / "artifacts" / "simulation" / "pet_polycondensation_evidence.json"),
        help="Path to output verification JSON evidence artifact.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON directly to stdout.",
    )
    args = parser.parse_args()

    if _import_error is not None or run_pet_polycondensation_verification is None:
        payload = {
            "status": "failed",
            "error_code": "IMPORT_ERROR",
            "details": f"Failed to import run_pet_polycondensation_verification: {_import_error}",
            "data": {
                "work_package": "W236",
                "module": "pet_polycondensation",
                "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"{ESC_RED}[ERROR] Import failure: {_import_error}{ESC_RESET}", file=sys.stderr)
        return 1

    out_path = Path(args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    t0 = time.perf_counter()
    result = run_pet_polycondensation_verification(output_path=str(out_path))
    total_elapsed_ms = (time.perf_counter() - t0) * 1000.0

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{ESC_CYAN}{ESC_BOLD}========================================================================{ESC_RESET}")
        print(f"{ESC_CYAN}{ESC_BOLD}  W236 PET POLYCONDENSATION REACTOR 9-STAGE VERIFICATION SUITE         {ESC_RESET}")
        print(f"{ESC_CYAN}{ESC_BOLD}========================================================================{ESC_RESET}\n")

        stages = result.get("data", {}).get("stages", [])
        for s in stages:
            st_idx = s.get("stage", "?")
            st_chk = s.get("name", "unnamed_check")
            st_pass = s.get("passed", False)
            st_det = s.get("details", "")
            print(format_stage_result(st_idx, st_chk, st_pass, details=st_det))

        status = result.get("status", "unknown")
        checks_passed = result.get("data", {}).get("checks_passed", 0)
        total_checks = result.get("data", {}).get("total_checks", len(stages))

        print(f"\n{ESC_CYAN}------------------------------------------------------------------------{ESC_RESET}")
        if status == "success":
            print(f"  {ESC_GREEN}{ESC_BOLD}RESULT: SUCCESS ({checks_passed}/{total_checks} checks passed in {total_elapsed_ms:.1f}ms){ESC_RESET}")
        else:
            print(f"  {ESC_RED}{ESC_BOLD}RESULT: {status.upper()} ({checks_passed}/{total_checks} checks passed in {total_elapsed_ms:.1f}ms){ESC_RESET}")
        print(f"  Evidence written to: {ESC_DIM}{out_path}{ESC_RESET}\n")

    is_success = result.get("status") == "success"
    return 0 if is_success else 1


if __name__ == "__main__":
    sys.exit(main())
