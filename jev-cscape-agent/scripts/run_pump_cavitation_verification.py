"""Standalone CLI Verification Runner for W068 Pump Cavitation & NPSH Acoustic Forensics ODE."""

from __future__ import annotations

import json
from pathlib import Path
import sys

# Ensure repository root is in sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root / "src") not in sys.path:
    sys.path.insert(0, str(repo_root / "src"))
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from jev_cscape.simulation.pump_cavitation import verify_pump_cavitation_and_export_evidence


def main() -> int:
    evidence_path = repo_root / "artifacts" / "simulation" / "pump_cavitation_evidence.json"
    print("[*] Executing W068 Pump Cavitation & NPSH Forensics verification...")
    result = verify_pump_cavitation_and_export_evidence(output_evidence_path=str(evidence_path))
    print(json.dumps(result, indent=2))
    if result["status"] == "success":
        print(f"[+] Verification passed. Artifact written to:\n    {evidence_path}")
        return 0
    else:
        print(f"[-] Verification failed: {result['error_code']}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
