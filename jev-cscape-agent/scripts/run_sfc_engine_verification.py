"""Verification script for IEC 61131-3 Sequential Function Chart (SFC) Engine (W060).

Work Package: W060
Target Gate: Gate G4 (Closed-Loop Simulation) / Gate G1 (Pure ST AST Compliance)
4-State Contract: Returns strictly {"status": "success | failed | blocked | inconclusive"}
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

from jev_cscape.iec.sfc_engine import (
    verify_sfc_engine_and_export_evidence,
)


def main() -> int:
    evidence_file = Path("artifacts/simulation/sfc_engine_evidence.json")
    print(f"[*] Executing W060 IEC 61131-3 SFC Engine verification...")
    result = verify_sfc_engine_and_export_evidence(str(evidence_file))

    print(json.dumps(result, indent=2))
    if result.get("status") == "success":
        print(f"[+] Verification passed. Artifact written to {evidence_file}")
        return 0
    else:
        print(f"[-] Verification failed: {result.get('details')}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
