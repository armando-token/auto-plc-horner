#!/usr/bin/env python3
"""Verification Runner for Industrial mcl-PHA Biosynthesis ODE Simulation (W290).

Work Package: W290 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [mcl-PHA Biosynthesis Kinetics Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: initial_state_and_growth (verify inoculation growth)
  Stage 2: fatty_acid_substrate_kinetics (verify fatty acid substrate and nitrogen consumption)
  Stage 3: mcl_pha_polymer_accumulation (verify mcl-PHA polymer accumulation)
  Stage 4: tunable_c10_monomer_fraction (verify C10 monomer fraction within 50-80 mol%)
  Stage 5: substrate_toxicity_trip (verify 0xF901 trip upon fatty acid excess)
  Stage 6: nitrogen_starvation_trip (verify 0xF902 trip upon premature nitrogen starvation)
  Stage 7: thermal_and_oxygen_trips (verify 0xF903 and 0xF904 trips)
  Stage 8: elemental_conservation_residuals (verify elemental mass residual < 1e-10)
  Stage 9: horner_ocs_register_sync_and_pure_st (verify %R2510..%R2517, %M585..%M587 and Pure ST)

Generates:
  artifacts/simulation/mcl_pha_biosynthesis_evidence.json
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

from jev_cscape.simulation.mcl_pha_biosynthesis import (
    run_mcl_pha_biosynthesis_verification,
)

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
        description="Execute W290 mcl-PHA Biosynthesis 9-Stage Verification Suite."
    )
    parser.add_argument(
        "positional_output",
        nargs="?",
        default=None,
        help="Optional positional path to write JSON evidence artifact.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Path to output verification JSON evidence artifact.",
    )
    parser.add_argument(
        "--work-package",
        type=str,
        default="W290",
        help="Work package identifier (default: W290).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON directly to stdout.",
    )
    args = parser.parse_args(argv)

    default_evidence = REPO_ROOT / "artifacts" / "simulation" / "mcl_pha_biosynthesis_evidence.json"
    out_path_str = args.output or args.positional_output or str(default_evidence)
    out_path = Path(out_path_str).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    t0 = time.perf_counter()
    result = run_mcl_pha_biosynthesis_verification(
        output_path=str(out_path),
        work_package=args.work_package,
    )
    elapsed_total_ms = (time.perf_counter() - t0) * 1000.0

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result.get("status") == "success" else 1

    print("\n" + "=" * 76)
    print(f"  {args.work_package} MCL-PHA BIOSYNTHESIS 9-STAGE VERIFICATION SUITE")
    print("=" * 76 + "\n")

    stages = result.get("data", {}).get("stages") or result.get("data", {}).get("tests", [])
    for st in stages:
        st_num = st.get("stage", "?")
        check_name = st.get("name", st.get("check", "Stage Check"))
        passed = st.get("passed", False)
        details = st.get("details", "")
        timing = st.get("timing_ms")
        print(format_stage_result(st_num, check_name, passed, timing_ms=timing, details=details))

    overall_status = result.get("status", "failed")
    passed_count = result.get("data", {}).get("checks_passed", 0)
    total_count = result.get("data", {}).get("total_checks", len(stages))

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
