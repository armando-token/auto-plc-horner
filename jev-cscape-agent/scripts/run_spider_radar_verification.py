#!/usr/bin/env python3
"""Run Cscape HMI Dynamic Spider / Radar Polar Diagnostic Pentagon Chart Verification.

Work Package: W084 (Gate G9 / G2)
Generates:
- artifacts/HMI/spider_radar_evidence.json
- artifacts/HMI/spider_sample.svg
"""

import os
import sys

# Ensure repository root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from jev_cscape.hmi.spider_radar import run_spider_radar_verification


def main() -> int:
    evidence_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "artifacts", "HMI", "spider_radar_evidence.json")
    )
    svg_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "artifacts", "HMI", "spider_sample.svg")
    )
    print(f"[*] Running Spider / Radar Polar Diagnostic Chart Verification...")
    evidence = run_spider_radar_verification(evidence_path, svg_path)

    passed_count = sum(1 for t in evidence["data"]["tests"] if t["passed"])
    total_count = len(evidence["data"]["tests"])
    print(f"[*] Verification complete: {passed_count}/{total_count} checks passed.")
    print(f"[*] Status: {evidence['status']}")
    print(f"[*] Evidence written to: {evidence_path}")
    print(f"[*] SVG sample written to: {svg_path}")

    return 0 if evidence["status"] == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
