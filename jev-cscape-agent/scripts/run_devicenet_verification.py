#!/usr/bin/env python3
"""Verification Script for Industrial DeviceNet Master Protocol Engine (W106).

Work Package: W106 (Gate G8 / G4)
Status Contract: Strict 4-State JSON output & evidence emission.

Generates:
  artifacts/telemetry/devicenet_evidence.json
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from jev_cscape.telemetry.devicenet import run_devicenet_verification


def main() -> int:
    evidence_path = REPO_ROOT / "artifacts" / "telemetry" / "devicenet_evidence.json"
    print("=" * 80)
    print("  JEV Cscape Agent: DeviceNet Master Protocol Engine Verification (W106)")
    print("=" * 80)

    evidence = run_devicenet_verification(str(evidence_path))

    tests = evidence["data"]["tests"]
    for t in tests:
        st = "PASS" if t["passed"] else "FAIL"
        print(f"  Stage {t['stage']}: [{st}] {t['check']}")

    print("-" * 80)
    checks_passed = evidence["data"]["checks_passed"]
    total_checks = evidence["data"]["total_checks"]
    print(f"[*] Outcome: {checks_passed}/{total_checks} checks passed.")
    print(f"[*] Status: {evidence['status']}")
    print(f"[*] Evidence artifact saved: {evidence_path.resolve()}")
    print("=" * 80)

    return 0 if evidence["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
