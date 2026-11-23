"""Verification script for Model Predictive Controller (MPC) Horizon Solver (W061).

Work Package: W061
Target Gate: Gate G4 (Closed-Loop Simulation) / Gate G7 (Advanced Plant Dynamics & Optimization)
4-State Contract: Returns strictly {"status": "success | failed | blocked | inconclusive"}
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

from jev_cscape.simulation.mpc_controller import (
    verify_mpc_controller_and_export_evidence,
)


def main() -> int:
    evidence_file = Path("artifacts/simulation/mpc_controller_evidence.json")
    print("[*] Executing W061 MPC Controller verification...")
    result = verify_mpc_controller_and_export_evidence(str(evidence_file))

    print(json.dumps(result, indent=2))
    if result.get("status") == "success":
        print(f"[+] Verification passed. Artifact written to {evidence_file}")
        return 0
    else:
        print(f"[-] Verification failed: {result.get('details')}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
