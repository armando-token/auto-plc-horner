#!/usr/bin/env python3
"""Verification Script for Industrial Polyethylene Terephthalate (PET) Continuous Esterification ODE Simulation (W254).

Work Package: W254 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Rigorous Process Physics & Numerical Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: PET Esterification Chemistry & Thermochemical Enthalpies
  Stage 2: Pure IEC 61131-3 ST POU Validation with STParser and SecurityGuard
  Stage 3: Anti-Ladder Security Guard Interception
  Stage 4: Nominal Steady-State Closed-Loop Convergence (Conversion >= 95.0%, Yield >= 90.0%, Temp 240.0 °C, Pressure 2.80 bar)
  Stage 5: Conservation Laws Verification (mass error < 1e-10 kg/s, enthalpy error < 1e-10 kW)
  Stage 6: Thermal Runaway & Emergency Depressurization Trip (0xF501, %M503)
  Stage 7: EG Depletion Pre-Alarm & Condenser Fault Injections (0xF502, %M502)
  Stage 8: Horner OCS Register Table Synchronization (%R2150..%R2157, %M501..%M503)
  Stage 9: Simulation Soak 100 Cycles & Dynamic Settling Stability

Generates:
  artifacts/simulation/pet_esterification_evidence.json
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
    from jev_cscape.simulation.pet_esterification import (
        run_pet_esterification_verification,
    )
    _import_error = None
except ImportError as exc:
    try:
        from jev_cscape.simulation import run_pet_esterification_verification
        _import_error = None
    except ImportError:
        run_pet_esterification_verification = None
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


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute W254 PET Esterification 9-Stage Verification Suite."
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=str(REPO_ROOT / "artifacts" / "simulation" / "pet_esterification_evidence.json"),
        help="Path to output verification JSON evidence artifact.",
    )
    parser.add_argument(
        "--work-package",
        type=str,
        default="W254",
        help="Work package identifier (default: W254).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON directly to stdout.",
    )
    args = parser.parse_args(argv)

    if _import_error is not None or run_pet_esterification_verification is None:
        payload = {
            "status": "failed",
            "error_code": "IMPORT_ERROR",
            "details": f"Failed to import run_pet_esterification_verification: {_import_error}",
            "data": {
                "work_package": args.work_package,
                "module": "pet_esterification",
                "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"{ESC_RED}ERROR: Failed to import verification suite: {_import_error}{ESC_RESET}", file=sys.stderr)
        return 1

    t0 = time.perf_counter()
    out_path = Path(args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    result = run_pet_esterification_verification(output_path=out_path)
    elapsed_total_ms = (time.perf_counter() - t0) * 1000.0

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result.get("status") == "success" else 1

    print("\n" + "=" * 76)
    print(f"  {args.work_package} PET ESTERIFICATION 9-STAGE VERIFICATION SUITE")
    print("=" * 76 + "\n")

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

    print("\n" + "-" * 76)
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
