#!/usr/bin/env python3
"""Verification Runner for Cscape HMI Dynamic Sankey Flow Diagram Vector Canvas.

Work Package: W087 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Generates:
  artifacts/HMI/sankey_flow_evidence.json
  artifacts/HMI/sankey_sample.svg
"""

import os
from pathlib import Path
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from jev_cscape.hmi.sankey_flow import run_sankey_flow_verification


def main() -> int:
    evidence_path = REPO_ROOT / "artifacts" / "HMI" / "sankey_flow_evidence.json"
    svg_path = REPO_ROOT / "artifacts" / "HMI" / "sankey_sample.svg"

    print("=" * 80)
    print("  JEV Cscape Agent: HMI Dynamic Sankey Flow Diagram Canvas Verification (W087)")
    print("=" * 80)

    evidence = run_sankey_flow_verification(evidence_path=str(evidence_path), svg_path=str(svg_path))

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
    print(f"[*] Vector SVG artifact saved: {svg_path}")
    print("=" * 80)

    return 0 if evidence["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
