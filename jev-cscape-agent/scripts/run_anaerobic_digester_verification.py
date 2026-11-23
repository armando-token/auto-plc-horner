#!/usr/bin/env python3
"""Verification Script for Industrial Anaerobic Digester & Biogas Methanogenesis Dynamics ODE Simulation (W122).

Work Package: W122 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Rigorous Process Physics & Numerical Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/simulation/anaerobic_digester_evidence.json
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

from jev_cscape.simulation.anaerobic_digester import run_anaerobic_digester_verification

# ANSI Terminal Colors
ANSI_GREEN = "\033[92m"
ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_CYAN = "\033[96m"
ANSI_BOLD = "\033[1m"
ANSI_RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verification Runner for Industrial Anaerobic Digester & Biogas Methanogenesis Dynamics ODE Simulation (W122)."
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
        REPO_ROOT / "artifacts" / "simulation" / "anaerobic_digester_evidence.json"
    )
    evidence_path = Path(target_path_str)
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"{ANSI_BOLD}{'=' * 80}{ANSI_RESET}")
    print(f"  {ANSI_BOLD}JEV Cscape Agent: Industrial Anaerobic Digester & Biogas Methanogenesis Verification (W122){ANSI_RESET}")
    print(f"{ANSI_BOLD}{'=' * 80}{ANSI_RESET}")

    try:
        sig = inspect.signature(run_anaerobic_digester_verification)
        if "evidence_path" in sig.parameters:
            evidence = run_anaerobic_digester_verification(evidence_path=str(evidence_path))
        elif "output_path" in sig.parameters:
            evidence = run_anaerobic_digester_verification(output_path=str(evidence_path))
        else:
            evidence = run_anaerobic_digester_verification(str(evidence_path))
    except TypeError:
        evidence = run_anaerobic_digester_verification(str(evidence_path))

    tests = evidence.get("data", {}).get("tests", [])
    if not tests and "stages" in evidence.get("data", {}):
        tests = evidence["data"]["stages"]

    for t in tests:
        stage = t.get("stage", "?")
        check = t.get("check") or t.get("name") or "Unnamed_Check"
        passed = t.get("passed", False)
        status = t.get("status", "passed" if passed else "failed")
        details = t.get("details", "")

        if passed or status == "passed":
            st_badge = f"{ANSI_GREEN}PASS{ANSI_RESET}"
        elif status == "blocked":
            st_badge = f"{ANSI_YELLOW}BLOCKED{ANSI_RESET}"
        else:
            st_badge = f"{ANSI_RED}FAIL{ANSI_RESET}"

        line = f"  Stage {stage}: [{st_badge}] {check}"
        if details:
            line += f"\n           {details}"
        print(line)

    print(f"{ANSI_BOLD}{'-' * 80}{ANSI_RESET}")
    checks_passed = evidence.get("data", {}).get("checks_passed", sum(1 for t in tests if t.get("passed", False)))
    total_checks = evidence.get("data", {}).get("total_checks", len(tests))
    status_str = evidence.get("status", "failed")

    if status_str == "success":
        status_disp = f"{ANSI_GREEN}{status_str}{ANSI_RESET}"
    elif status_str == "blocked":
        status_disp = f"{ANSI_YELLOW}{status_str}{ANSI_RESET}"
    else:
        status_disp = f"{ANSI_RED}{status_str}{ANSI_RESET}"

    print(f"[*] Outcome: {checks_passed}/{total_checks} checks passed.")
    print(f"[*] Status: {status_disp}")
    print(f"[*] Evidence artifact saved: {ANSI_CYAN}{evidence_path.resolve()}{ANSI_RESET}")
    print(f"{ANSI_BOLD}{'=' * 80}{ANSI_RESET}")

    return 0 if status_str == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
