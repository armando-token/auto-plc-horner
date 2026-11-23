#!/usr/bin/env python3
"""Run Batch Vacuum Evaporative Crystallizer Population Balance Equations & MOM ODE Verification.

Work Package: W083 (Gate G7 / G4)
Generates: artifacts/simulation/crystallizer_evidence.json
"""

import os
import sys

# Ensure repository root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from jev_cscape.simulation.crystallizer import run_crystallizer_verification


def main() -> int:
    evidence_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "artifacts", "simulation", "crystallizer_evidence.json")
    )
    print(f"[*] Running Crystallizer PBE Method of Moments ODE Verification...")
    evidence = run_crystallizer_verification(evidence_path)

    passed_count = sum(1 for t in evidence["data"]["tests"] if t["passed"])
    total_count = len(evidence["data"]["tests"])
    print(f"[*] Verification complete: {passed_count}/{total_count} checks passed.")
    print(f"[*] Status: {evidence['status']}")
    print(f"[*] Evidence written to: {evidence_path}")

    return 0 if evidence["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
