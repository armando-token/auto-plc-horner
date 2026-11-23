#!/usr/bin/env python3
"""Verification Script for Industrial FOUNDATION Fieldbus H1 Master Protocol Engine (W109).

Work Package: W109 (Gate G8 / G4)
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/telemetry/fieldbus_evidence.json
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

from jev_cscape.telemetry.fieldbus import run_fieldbus_verification


def main() -> int:
    evidence_path = REPO_ROOT / "artifacts" / "telemetry" / "fieldbus_evidence.json"
    print("=" * 80)
    print("  JEV Cscape Agent: FOUNDATION Fieldbus H1 Master Protocol Engine Verification (W109)")
    print("=" * 80)

    evidence = run_fieldbus_verification(str(evidence_path))

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
