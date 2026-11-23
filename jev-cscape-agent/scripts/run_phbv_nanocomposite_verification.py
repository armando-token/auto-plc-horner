#!/usr/bin/env python3
"""Verification Runner for Industrial PHBV Nanocomposite Biopolymer Biosynthesis ODE Simulation (W296).

Work Package: W296 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Nanocomposite Copolymer Biosynthesis Kinetics Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: initial_state_and_growth (verify inoculation growth)
  Stage 2: coupled_substrate_kinetics (verify glucose and valerate consumption)
  Stage 3: nanocomposite_polymer_accumulation (verify PHBV nanocomposite accumulation)
  Stage 4: tunable_3hv_mol_fraction (verify 3HV mole fraction within 5-30 mol%)
  Stage 5: precursor_toxicity_trip (verify 0xF921 trip and dosing shutdown)
  Stage 6: nanofiller_agglomeration_trip (verify 0xF922 trip on dispersion loss)
  Stage 7: thermal_runaway_trip (verify 0xF923 trip upon high temperature)
  Stage 8: do_starvation_and_mass_conservation (verify 0xF924 trip and elemental mass residual < 1e-10)
  Stage 9: horner_ocs_register_sync (verify %R2570..%R2577 and %M599..%M601 sync)

Generates:
  artifacts/simulation/phbv_nanocomposite_evidence.json
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

from jev_cscape.simulation.phbv_nanocomposite import (
    run_phbv_nanocomposite_verification,
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
        description="Execute W296 PHBV Nanocomposite Biosynthesis 9-Stage Verification Suite."
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
        default="W296",
        help="Work package identifier (default: W296).",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress terminal output and emit only exit code.",
    )
    parser.add_argument(
        "--json",
        "--json-only",
        action="store_true",
        help="Emit raw JSON report only (no ANSI stdout banner).",
    )

    args = parser.parse_args(argv)

    output_path = args.output or args.positional_output
    if not output_path:
        default_artifact = (
            REPO_ROOT / "artifacts" / "simulation" / "phbv_nanocomposite_evidence.json"
        )
        output_path = str(default_artifact)

    if not args.quiet and not args.json:
        print(f"\n{ESC_BOLD}{ESC_CYAN}================================================================{ESC_RESET}")
        print(f"{ESC_BOLD}{ESC_CYAN}  JEV Cscape - Wave {args.work_package} PHBV Nanocomposite Verification{ESC_RESET}")
        print(f"{ESC_BOLD}{ESC_CYAN}================================================================{ESC_RESET}")
        print(f"  Target artifact: {output_path}\n")

    t_start = time.perf_counter()
    evidence = run_phbv_nanocomposite_verification(
        output_path=output_path,
        work_package=args.work_package,
    )
    elapsed_total_ms = (time.perf_counter() - t_start) * 1000.0

    if args.json:
        print(json.dumps(evidence, indent=2))
        return 0 if evidence.get("status") == "success" else 1

    if not args.quiet:
        stages = evidence.get("data", {}).get("stages", [])
        for s in stages:
            print(
                format_stage_result(
                    stage=s.get("stage", "?"),
                    check=s.get("name", "unnamed"),
                    passed=bool(s.get("passed", False)),
                    timing_ms=s.get("timing_ms"),
                    details=s.get("details", ""),
                )
            )

        print(f"\n{ESC_BOLD}Summary:{ESC_RESET}")
        print(f"  Status:       {evidence.get('status')}")
        print(
            f"  Checks:       {evidence.get('data', {}).get('checks_passed')}/"
            f"{evidence.get('data', {}).get('total_checks')} passed"
        )
        print(f"  Total time:   {elapsed_total_ms:.2f} ms")
        print(f"  Evidence:     {output_path}\n")

    return 0 if evidence.get("status") == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
