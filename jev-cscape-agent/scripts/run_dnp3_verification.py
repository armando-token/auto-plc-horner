"""Verification script for Industrial DNP3 / IEEE 1815 Telemetry (W070 / Gate G8)."""

from __future__ import annotations

import json
import os
import sys

# Ensure src/ is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from jev_cscape.telemetry.dnp3 import verify_dnp3_and_export_evidence


def main() -> int:
    evidence_path = os.path.abspath("artifacts/telemetry/dnp3_evidence.json")
    print(f"Running DNP3 Telemetry protocol verification -> {evidence_path}")
    result = verify_dnp3_and_export_evidence(evidence_path)
    print(json.dumps(result, indent=2))
    if result["status"] == "success":
        print("\n[SUCCESS] W070 DNP3 Telemetry verification passed cleanly.")
        return 0
    else:
        print(f"\n[FAILED] Verification failed: {result['error_code']}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
