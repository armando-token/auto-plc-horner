#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Chernoff Face Process Anomaly Avatar (W096).

Work Package: W096 (Gate G9 / G2)
Status Contract: Strict 4-State JSON output & evidence emission.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

from jev_cscape.hmi.chernoff_avatar import run_chernoff_avatar_verification


def main() -> int:
    evidence_path = Path("artifacts/HMI/chernoff_avatar_evidence.json")
    svg_path = Path("artifacts/HMI/chernoff_avatar_sample.svg")

    print("=" * 80)
    print("  JEV Cscape Agent: Chernoff Face Process Anomaly Avatar Verification (W096)")
    print("=" * 80)

    evidence = run_chernoff_avatar_verification(
        evidence_path=str(evidence_path),
        svg_path=str(svg_path),
    )

    for t in evidence["data"]["tests"]:
        st = "PASS" if t["passed"] else "FAIL"
        print(f"  Stage {t['stage']}: [{st}] {t['check']}")

    print("-" * 80)
    print(f"[*] Outcome: {evidence['data']['checks_passed']}/{evidence['data']['total_checks']} checks passed.")
    print(f"[*] Status: {evidence['status']}")
    print(f"[*] Evidence artifact saved: {evidence_path.resolve()}")
    print(f"[*] Sample SVG saved: {svg_path.resolve()}")
    print("=" * 80)

    return 0 if evidence["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
