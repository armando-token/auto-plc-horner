#!/usr/bin/env python3
"""Verification Script for Industrial Spray Drying Tower & Droplet Dynamics ODE Simulation (W107).

Work Package: W107 (Gate G7 / G4)
Status Contract: Strict 4-State JSON output & evidence emission.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from jev_cscape.simulation.spray_dryer import run_spray_dryer_verification


def main() -> int:
    evidence_path = Path("artifacts/simulation/spray_dryer_evidence.json")
    print("=" * 80)
    print("  JEV Cscape Agent: Spray Drying Tower Simulation Verification (W107)")
    print("=" * 80)

    evidence = run_spray_dryer_verification(str(evidence_path))

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
