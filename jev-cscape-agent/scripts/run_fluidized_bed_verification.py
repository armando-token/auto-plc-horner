#!/usr/bin/env python3
"""Verification Runner for Fluidized Bed Reactor (FBR) Two-Phase Hydrodynamics & Catalytic Gasification ODE Solver.

Work Package: W089 (Gate G7 / G4)
Classification: PRODUCTION_READY

Generates:
  artifacts/simulation/fluidized_bed_evidence.json
"""

import os
from pathlib import Path
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from jev_cscape.simulation.fluidized_bed import run_fluidized_bed_verification


def main() -> int:
    evidence_path = REPO_ROOT / "artifacts" / "simulation" / "fluidized_bed_evidence.json"
    print("=" * 80)
    print("  JEV Cscape Agent: Fluidized Bed Reactor (FBR) Simulation Verification (W089)")
    print("=" * 80)

    evidence = run_fluidized_bed_verification(str(evidence_path))

    tests = evidence["data"]["tests"]
    passed_count = sum(1 for t in tests if t["passed"])
    total_count = len(tests)

    for idx, test in enumerate(tests, 1):
        status_flag = "[PASS]" if test["passed"] else "[FAIL]"
        print(f"  Stage {idx}: {status_flag} {test['check']}")

    print("-" * 80)
    print(f"[*] Outcome: {passed_count}/{total_count} checks passed.")
    print(f"[*] Status: {evidence['status']}")
    print(f"[*] Evidence artifact saved: {evidence_path}")
    print("=" * 80)

    return 0 if evidence["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
