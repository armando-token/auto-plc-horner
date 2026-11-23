#!/usr/bin/env python3
"""Verification Script for Cscape HMI Voronoi Spatial Partitioning Canvas (W099).

Work Package: W099 (Gate G9 / G2)
Status Contract: Strict 4-State JSON output & evidence emission.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

from jev_cscape.hmi.voronoi_partition import run_voronoi_partition_verification


def main() -> int:
    evidence_path = Path("artifacts/HMI/voronoi_partition_evidence.json")
    svg_path = Path("artifacts/HMI/voronoi_partition_sample.svg")
    print("=" * 80)
    print("  JEV Cscape Agent: HMI Voronoi Spatial Partitioning Verification (W099)")
    print("=" * 80)

    evidence = run_voronoi_partition_verification(str(evidence_path), str(svg_path))

    for t in evidence["data"]["tests"]:
        st = "PASS" if t["passed"] else "FAIL"
        print(f"  Stage {t['stage']}: [{st}] {t['check']}")

    print("-" * 80)
    print(f"[*] Outcome: {evidence['data']['checks_passed']}/{evidence['data']['total_checks']} checks passed.")
    print(f"[*] Status: {evidence['status']}")
    print(f"[*] Evidence artifact saved: {evidence_path.resolve()}")
    print(f"[*] SVG canvas artifact saved: {svg_path.resolve()}")
    print("=" * 80)

    return 0 if evidence["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
