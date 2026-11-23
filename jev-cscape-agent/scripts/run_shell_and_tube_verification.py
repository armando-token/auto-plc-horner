#!/usr/bin/env python3
"""Verification Script for Shell-and-Tube Exchanger Dynamics ODE Solver (W095).

Work Package: W095 (Gate G7 / G4)
Status Contract: Strict 4-State JSON output & evidence emission.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

from jev_cscape.simulation.shell_and_tube import run_shell_and_tube_verification


def main() -> int:
    evidence_path = Path("artifacts/simulation/shell_and_tube_evidence.json")
    print("=" * 80)
    print("  JEV Cscape Agent: Shell-and-Tube Exchanger Dynamics Verification (W095)")
    print("=" * 80)

    evidence = run_shell_and_tube_verification(str(evidence_path))

    for t in evidence["data"]["tests"]:
        st = "PASS" if t["passed"] else "FAIL"
        print(f"  Stage {t['stage']}: [{st}] {t['check']}")

    print("-" * 80)
    print(f"[*] Outcome: {evidence['data']['checks_passed']}/{evidence['data']['total_checks']} checks passed.")
    print(f"[*] Status: {evidence['status']}")
    print(f"[*] Evidence artifact saved: {evidence_path.resolve()}")
    print("=" * 80)

    return 0 if evidence["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
