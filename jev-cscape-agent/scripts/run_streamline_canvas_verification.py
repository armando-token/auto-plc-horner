#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Streamline Vector Field & Fluid Velocity Flowline Canvas (W108).

Work Package: W108 (Gate G9 / G2)
Status Contract: Strict 4-State JSON output & evidence emission.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

from jev_cscape.hmi.streamline_canvas import run_streamline_canvas_verification


def main() -> int:
    evidence_path = Path("artifacts/HMI/streamline_canvas_evidence.json")
    svg_path = Path("artifacts/HMI/streamline_canvas_sample.svg")
    print("=" * 80)
    print("  JEV Cscape Agent: Streamline Vector Field & Flowline Canvas Verification (W108)")
    print("=" * 80)

    evidence = run_streamline_canvas_verification(
        evidence_path=str(evidence_path),
        svg_export_path=str(svg_path),
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
