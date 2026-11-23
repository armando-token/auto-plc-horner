"""Verification Runner for ANSI/ISA-88 Batch Phase Engine.

Work Package: W057 (Gate G4 Simulation / Gate G9 Control Logic)
Executes ANSI/ISA-88 state model transitions, 7-phase recipe progression,
safety interlocks, and exports artifacts/simulation/batch_phase_evidence.json.
"""

import json
import sys
from pathlib import Path

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root / "src"))

from jev_cscape.simulation.batch_phase_engine import verify_batch_phase_engine_and_export_evidence


def main() -> int:
    out_file = repo_root / "artifacts" / "simulation" / "batch_phase_evidence.json"
    print(f"[W057] Executing ANSI/ISA-88 Batch Phase Engine verification...")
    result = verify_batch_phase_engine_and_export_evidence(str(out_file))
    print(f"[W057] Status: {result.get('status')}")
    print(f"[W057] Details: {result.get('details')}")

    if result.get("status") == "success":
        data = result.get("data", {})
        isa = data.get("isa88_state_model", {})
        rec = data.get("recipe_sequence", {})
        print(f"[W057] States Verified: {isa.get('total_states')} (Command order: {isa.get('command_priority_order')})")
        print(f"[W057] Recipe: '{rec.get('recipe_name')}' with {rec.get('total_phases')} phases")
        print(f"[W057] Evidence written to: {out_file}")
        return 0
    else:
        print(f"[W057] ERROR: Batch phase verification failed: {result.get('error_code')}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
