#!/usr/bin/env python3
"""Verification Runner for Multi-Tank Pneumatic Pressure Regulation & Compressible Gas ODE Solver (W065).

Generates:
- artifacts/simulation/pneumatic_system_evidence.json (deterministic 4-state evidence)
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from jev_cscape.simulation.pneumatic_system import verify_pneumatic_system_and_export_evidence


def main() -> int:
    evidence_path = PROJECT_ROOT / "artifacts" / "simulation" / "pneumatic_system_evidence.json"

    print("[*] Executing W065 Pneumatic System verification...")
    result = verify_pneumatic_system_and_export_evidence(
        output_evidence_path=str(evidence_path),
    )

    print(json.dumps(result, indent=2))

    if result.get("status") == "success":
        print(f"[+] Verification passed. Artifact written to:\n    {evidence_path}")
        return 0
    else:
        print(f"[-] Verification failed: {result.get('details')}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
