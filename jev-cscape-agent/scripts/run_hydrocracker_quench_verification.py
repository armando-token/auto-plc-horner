#!/usr/bin/env python3
"""Verification Script for Industrial Hydrocracking Heavy Gas Oil Trickle-Bed Hydrodynamics & Cracking Quench ODE Simulation (W176).

Work Package: W176 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Rigorous Process Physics & Numerical Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/simulation/hydrocracker_quench_evidence.json
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from jev_cscape.simulation.hydrocracker_quench import run_hydrocracker_quench_verification
except ImportError:
    try:
        from jev_cscape.simulation import run_hydrocracker_quench_verification
    except ImportError:
        run_hydrocracker_quench_verification = None

# ANSI Terminal Colors
ANSI_GREEN = "\033[92m"
ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_CYAN = "\033[96m"
ANSI_BOLD = "\033[1m"
ANSI_RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verification Runner for Industrial Hydrocracking Heavy Gas Oil Trickle-Bed Hydrodynamics & Cracking Quench ODE Simulation (W176)."
    )
    parser.add_argument(
        "positional_evidence",
        nargs="?",
        default=None,
        help="Target output path for verification evidence JSON artifact.",
    )
    parser.add_argument(
        "--evidence",
        "--output",
        "-o",
        dest="flag_evidence",
        default=None,
        help="Flagged target path for verification evidence JSON artifact.",
    )
    args = parser.parse_args(argv)

    target_path_str = args.flag_evidence or args.positional_evidence or str(
        REPO_ROOT / "artifacts" / "simulation" / "hydrocracker_quench_evidence.json"
    )
    evidence_path = Path(target_path_str)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"{ANSI_BOLD}{'=' * 80}{ANSI_RESET}")
    print(f"  {ANSI_BOLD}JEV Cscape Agent: Hydrocracker Quench Simulation Verification (W176){ANSI_RESET}")
    print(f"{ANSI_BOLD}{'=' * 80}{ANSI_RESET}")

    if run_hydrocracker_quench_verification is None:
        print(f"  {ANSI_RED}ERROR: Failed to import run_hydrocracker_quench_verification from jev_cscape.simulation.hydrocracker_quench{ANSI_RESET}")
        print(f"{ANSI_BOLD}{'=' * 80}{ANSI_RESET}\n")
        return 1

    try:
        sig = inspect.signature(run_hydrocracker_quench_verification)
        if "output_path" in sig.parameters:
            evidence = run_hydrocracker_quench_verification(output_path=str(evidence_path))
        elif "evidence_path" in sig.parameters:
            evidence = run_hydrocracker_quench_verification(evidence_path=str(evidence_path))
        elif "target_path" in sig.parameters:
            evidence = run_hydrocracker_quench_verification(target_path=str(evidence_path))
        else:
            evidence = run_hydrocracker_quench_verification(str(evidence_path))
    except TypeError:
        evidence = run_hydrocracker_quench_verification(str(evidence_path))

    tests = evidence.get("data", {}).get("tests", [])
    if not tests and "stages" in evidence.get("data", {}):
        tests = evidence["data"]["stages"]

    for t in tests:
        stage = t.get("stage", "?")
        check = t.get("check") or t.get("name") or "Unnamed_Check"
        passed = t.get("passed", False)
        details = t.get("details", "")
        status_badge = f"{ANSI_GREEN}PASS{ANSI_RESET}" if passed else f"{ANSI_RED}FAIL{ANSI_RESET}"
        print(f"  Stage {stage:2} [{status_badge}] {ANSI_CYAN}{check}{ANSI_RESET}")
        if details:
            print(f"            {details}")

    overall_status = evidence.get("status", "failed")
    checks_passed = evidence.get("data", {}).get("checks_passed", 0)
    total_checks = evidence.get("data", {}).get("total_checks", len(tests))

    print(f"\n{ANSI_BOLD}{'-' * 80}{ANSI_RESET}")
    if overall_status == "success":
        print(f"  {ANSI_GREEN}{ANSI_BOLD}VERIFICATION SUCCESSFUL: {checks_passed}/{total_checks} checks passed cleanly.{ANSI_RESET}")
        print(f"  Evidence recorded to: {ANSI_CYAN}{evidence_path}{ANSI_RESET}")
        print(f"{ANSI_BOLD}{'=' * 80}{ANSI_RESET}\n")
        return 0
    else:
        print(f"  {ANSI_RED}{ANSI_BOLD}VERIFICATION FAILED: Only {checks_passed}/{total_checks} checks passed.{ANSI_RESET}")
        print(f"  Error code: {evidence.get('error_code', 'UNKNOWN_ERROR')}")
        print(f"{ANSI_BOLD}{'=' * 80}{ANSI_RESET}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
