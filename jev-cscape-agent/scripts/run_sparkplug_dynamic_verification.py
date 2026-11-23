#!/usr/bin/env python3
"""Verification Runner for Industrial MQTT Sparkplug B Dynamic Metric Definition & Complex UDT Datagroup Engine.

Work Package: W091 (Gate G8 / G4)
Classification: PRODUCTION_READY

Generates:
  artifacts/telemetry/sparkplug_dynamic_evidence.json
"""

import os
from pathlib import Path
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from jev_cscape.telemetry.sparkplug_dynamic import run_sparkplug_dynamic_verification


def main() -> int:
    evidence_path = REPO_ROOT / "artifacts" / "telemetry" / "sparkplug_dynamic_evidence.json"
    print("=" * 80)
    print("  JEV Cscape Agent: Sparkplug B Dynamic Metric & UDT Engine Verification (W091)")
    print("=" * 80)

    evidence = run_sparkplug_dynamic_verification(str(evidence_path))

    tests = evidence["data"]["tests"]
    passed_count = sum(1 for t in tests if t["passed"])
    total_count = len(tests)

    for idx, test in enumerate(tests, 1):
        status_flag = "[PASS]" if test["passed"] else "[FAIL]"
        print(f"  Stage {idx}: {status_flag} {test['check']}")

    print("-" * 80)
    print(f"[*] Outcome: {passed_count}/{total_count} checks passed.")
    print(f"[*] Status: {evidence['status']}")
    print(f"[*] Evidence artifact saved: {evidence_path}")
    print("=" * 80)

    return 0 if evidence["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
