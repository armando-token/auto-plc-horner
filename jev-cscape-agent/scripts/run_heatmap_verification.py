#!/usr/bin/env python3
"""Verification Runner for Cscape HMI Dynamic Cartesian Heatmap & Thermal Dispersion Matrix Rasterizer.

Work Package: W090 (Gate G9 / G2)
Classification: PRODUCTION_READY

Generates:
  artifacts/HMI/cartesian_heatmap_evidence.json
  artifacts/HMI/heatmap_sample.svg
"""

import os
from pathlib import Path
import sys

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from jev_cscape.hmi.cartesian_heatmap import run_heatmap_verification


def main() -> int:
    evidence_path = REPO_ROOT / "artifacts" / "HMI" / "cartesian_heatmap_evidence.json"
    svg_path = REPO_ROOT / "artifacts" / "HMI" / "heatmap_sample.svg"

    print("=" * 80)
    print("  JEV Cscape Agent: HMI Cartesian Heatmap Rasterizer Verification (W090)")
    print("=" * 80)

    evidence = run_heatmap_verification(str(evidence_path), str(svg_path))

    tests = evidence["data"]["tests"]
    passed_count = sum(1 for t in tests if t["passed"])
    total_count = len(tests)

    for idx, test in enumerate(tests, 1):
        status_flag = "[PASS]" if test["passed"] else "[FAIL]"
        print(f"  Stage {idx}: {status_flag} {test['check']}")

    print("-" * 80)
    print(f"[*] Outcome: {passed_count}/{total_count} checks passed.")
    print(f"[*] Status: {evidence['status']}")
    print(f"[*] Contrast Ratio: {evidence['data']['contrast_ratio_aaa']}")
    print(f"[*] Evidence artifact saved: {evidence_path}")
    print(f"[*] Vector SVG rendered: {svg_path}")
    print("=" * 80)

    return 0 if evidence["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
