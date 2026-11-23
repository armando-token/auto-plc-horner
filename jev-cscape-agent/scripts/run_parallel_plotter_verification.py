#!/usr/bin/env python3
"""Verification Script for Parallel Coordinate Plotter & Corridor Rasterizer (W093).

Work Package: W093 (Gate G9 / G2)
Status Contract: Strict 4-State JSON output & evidence emission.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

from jev_cscape.hmi.parallel_coordinate_plotter import run_parallel_plotter_verification


def main() -> int:
    evidence_path = Path("artifacts/HMI/parallel_plotter_evidence.json")
    svg_output_path = Path("artifacts/HMI/parallel_plotter_sample.svg")

    print("=" * 80)
    print("  JEV Cscape Agent: Parallel Coordinate Trajectory Plotter Verification (W093)")
    print("=" * 80)

    evidence = run_parallel_plotter_verification(
        evidence_path=str(evidence_path),
        svg_output_path=str(svg_output_path),
    )

    for t in evidence["data"]["tests"]:
        st = "PASS" if t["passed"] else "FAIL"
        print(f"  Stage {t['stage']}: [{st}] {t['check']}")

    print("-" * 80)
    print(f"[*] Outcome: {evidence['data']['checks_passed']}/{evidence['data']['total_checks']} checks passed.")
    print(f"[*] Status: {evidence['status']}")
    print(f"[*] Evidence artifact saved: {evidence_path.resolve()}")
    print(f"[*] SVG sample graphic saved: {svg_output_path.resolve()}")
    print("=" * 80)

    return 0 if evidence["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
