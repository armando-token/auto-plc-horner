#!/usr/bin/env python3
"""Verification Script for Biomass Fast Pyrolysis Fluidized Bed Reactor Engine (W113).

Work Package: W113 (Gate G7 Advanced Process Dynamics / Gate G4 Scan Cycle Simulation)
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/simulation/pyrolysis_evidence.json
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.simulation.pyrolysis import run_pyrolysis_verification


def main() -> int:
    evidence_path = REPO_ROOT / "artifacts" / "simulation" / "pyrolysis_evidence.json"
    print("=" * 80)
    print("  JEV Cscape Agent: Biomass Fast Pyrolysis Reactor Dynamics Verification (W113)")
    print("=" * 80)

    evidence = run_pyrolysis_verification(str(evidence_path))

    tests = evidence.get("data", {}).get("tests", [])
    for t in tests:
        st = "PASS" if t.get("passed") else "FAIL"
        print(f"  Stage {t.get('stage')}: [{st}] {t.get('check')}")

    print("-" * 80)
    checks_passed = evidence.get("data", {}).get("checks_passed", 0)
    total_checks = evidence.get("data", {}).get("total_checks", 0)
    print(f"[*] Outcome: {checks_passed}/{total_checks} checks passed.")
    print(f"[*] Status: {evidence.get('status')}")
    print(f"[*] Evidence artifact saved: {evidence_path.resolve()}")
    print("=" * 80)

    return 0 if evidence.get("status") == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
