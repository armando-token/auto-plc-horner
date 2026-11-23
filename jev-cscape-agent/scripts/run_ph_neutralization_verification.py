"""Verification script for Chemical Reactor pH Neutralization ODE (W071 / Gate G7 / Gate G4)."""

from __future__ import annotations

import json
import os
import sys

# Ensure src/ is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from jev_cscape.simulation.ph_neutralization import verify_ph_neutralization_and_export_evidence


def main() -> int:
    evidence_path = os.path.abspath("artifacts/simulation/ph_neutralization_evidence.json")
    print(f"Running pH Neutralization ODE verification -> {evidence_path}")
    result = verify_ph_neutralization_and_export_evidence(evidence_path)
    print(json.dumps(result, indent=2))
    if result["status"] == "success":
        print("\n[SUCCESS] W071 pH Neutralization verification passed cleanly.")
        return 0
    else:
        print(f"\n[FAILED] Verification failed: {result['error_code']}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
