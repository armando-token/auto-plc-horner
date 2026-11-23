#!/usr/bin/env python3
"""Verification Script for Industrial AS-Interface (AS-i v3.0 / IEC 62026-2) Master Protocol Engine (W103).

Work Package: W103 (Gate G8 / G4)
Status Contract: Strict 4-State JSON output & evidence emission.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

from jev_cscape.telemetry.asi import run_asi_verification


def main() -> int:
    evidence_path = Path("artifacts/telemetry/asi_evidence.json")
    print("=" * 80)
    print("  JEV Cscape Agent: AS-Interface v3.0 Master Protocol Engine Verification (W103)")
    print("=" * 80)

    evidence = run_asi_verification(str(evidence_path))

    for t in evidence["data"]["tests"]:
        st = "PASS" if t["passed"] else "FAIL"
        print(f"  Stage {t['stage']}: [{st}] {t['check']}")

    print("-" * 80)
    print(f"[*] Outcome: {evidence['data']['checks_passed']}/{evidence['data']['total_checks']} checks passed.")
    print(f"[*] Status: {evidence['status']}")
    print(f"[*] Evidence artifact saved: {evidence_path.resolve()}")
    print("=" * 80)

    return 0 if evidence["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
