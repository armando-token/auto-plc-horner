#!/usr/bin/env python3
"""Verification Script for Industrial ODVA CIP Safety Over Ethernet-APL Multi-Drop Trunk Protocol Engine (Wave W283).

Work Package: W283 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Standards & Specifications:
- IEEE 802.3cg-2019 / Ethernet-APL & 10BASE-T1S Multi-Drop (Clause 147 / Clause 148):
  - Physical Layer Collision Avoidance (PLCA - Clause 148)
  - Drop Cable / Spur Reflection & Termination Surveillance (Z0 = 100 Ohm, Gamma <= 0.15)
  - Bus Collision & Trunk Fault Interception (%M570)
- ODVA CIP Networks Library Volume 5: CIP Safety Specification (IEC 61784-3-2 / IEC 61508 SIL 3):
  - Dual 16-bit Safety CRCs (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B inverted data)
- Horner OCS Memory Space:
  - Analog registers %R2440..%R2447
  - Discrete coils %M569..%M570

Generates:
  artifacts/telemetry/cip_safety_apl_multidrop_evidence.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = REPO_ROOT / "src"
for p in (str(REPO_ROOT), str(SRC_PATH)):
    if p not in sys.path:
        sys.path.insert(0, p)

from jev_cscape.telemetry.cip_safety_apl_multidrop import (
    run_cip_safety_apl_multidrop_verification,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Execute W283 CIP Safety APL Multi-Drop Trunk Verification Suite"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=str(
            REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_apl_multidrop_evidence.json"
        ),
        help="Path to output JSON evidence artifact",
    )
    parser.add_argument(
        "--work-package",
        "-w",
        type=str,
        default="W283",
        help="Work package ID (default: W283)",
    )
    args = parser.parse_args()

    evidence = run_cip_safety_apl_multidrop_verification(
        output_path=args.output,
        work_package=args.work_package,
    )

    print(json.dumps(evidence, indent=2))
    return 0 if evidence.get("status") == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
