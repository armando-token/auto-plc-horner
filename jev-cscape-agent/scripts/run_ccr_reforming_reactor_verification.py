#!/usr/bin/env python3
"""Verification Script for Industrial Continuous Catalytic Reforming (CCR) Pin-Fin Radial Flow Chlorided-Alumina Reforming Reactor ODE Simulation (W185).

Work Package: W185 (Gate G7 Plant Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Rigorous Process Physics & Numerical Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/simulation/ccr_reforming_reactor_evidence.json
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
    from jev_cscape.simulation.ccr_reforming_reactor import (
        run_ccr_reforming_reactor_verification,
    )
except ImportError:
    try:
        from jev_cscape.simulation import run_ccr_reforming_reactor_verification
    except ImportError:
        run_ccr_reforming_reactor_verification = None

# ANSI Terminal Colors
ANSI_GREEN = "\033[92m"
ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_CYAN = "\033[96m"
ANSI_BOLD = "\033[1m"
ANSI_RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verification Runner for Industrial Continuous Catalytic Reforming (CCR) Pin-Fin Radial Flow Chlorided-Alumina Reforming Reactor ODE Simulation (W185)."
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
        help="Target output path for verification evidence JSON artifact.",
    )

    args = parser.parse_args(argv)
    output_path = (
        args.flag_evidence
        or args.positional_evidence
        or str(REPO_ROOT / "artifacts" / "simulation" / "ccr_reforming_reactor_evidence.json")
    )

    print(f"{ANSI_BOLD}{ANSI_CYAN}======================================================================{ANSI_RESET}")
    print(f"{ANSI_BOLD}{ANSI_CYAN}  CCR PIN-FIN RADIAL FLOW REFORMING REACTOR ODE VERIFICATION (W185)  {ANSI_RESET}")
    print(f"{ANSI_BOLD}{ANSI_CYAN}======================================================================{ANSI_RESET}\n")

    if run_ccr_reforming_reactor_verification is None:
        print(f"{ANSI_RED}Error: run_ccr_reforming_reactor_verification not found in jev_cscape.simulation.{ANSI_RESET}")
        return 1

    sig = inspect.signature(run_ccr_reforming_reactor_verification)
    if "output_path" in sig.parameters:
        result: Dict[str, Any] = run_ccr_reforming_reactor_verification(output_path=output_path)
    else:
        result = run_ccr_reforming_reactor_verification()
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

    status = result.get("status", "unknown")
    checks_passed = result.get("data", {}).get("checks_passed", 0)
    total_checks = result.get("data", {}).get("total_checks", 0)

    print(f"Status: {ANSI_GREEN if status == 'success' else ANSI_RED}{status.upper()}{ANSI_RESET}")
    print(f"Checks Passed: {checks_passed} / {total_checks}")
    print(f"Evidence Artifact: {output_path}\n")

    tests = result.get("data", {}).get("tests", [])
    for t in tests:
        stage = t.get("stage", "?")
        name = t.get("check", "unnamed")
        passed = t.get("passed", False)
        mark = f"{ANSI_GREEN}PASS{ANSI_RESET}" if passed else f"{ANSI_RED}FAIL{ANSI_RESET}"
        print(f"  Stage {stage} [{mark}] {name}: {t.get('details', '')}")

    print(f"\n{ANSI_BOLD}{ANSI_CYAN}======================================================================{ANSI_RESET}")
    return 0 if status == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
