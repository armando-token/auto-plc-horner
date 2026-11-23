#!/usr/bin/env python3
"""Verification Script for Industrial ODVA CIP Safety Over Ethernet-APL Star Topology Engine (Wave W289).

Work Package: W289 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [ODVA CIP Safety Over Ethernet-APL Star Topology]
Status Contract: Strict 4-State JSON output & evidence emission.

Features:
1. 10BASE-T1L Ethernet-APL Star Topology:
   - Implements star switch root and branch spur node models with port state transitions
     (DOWN -> LINK_UP -> FORWARDING).
   - Dedicated branch link loss surveillance and root switch failure detection (0xEE11, 0xEE12).
2. ODVA CIP Safety Frame Integrity:
   - Dual Safety CRC calculation:
     - CRC-S1: 16-bit generator polynomial 0x5935 over payload data.
     - CRC-S2: 16-bit generator polynomial 0x755B over inverted sequence number, timestamp, and SNN.
   - Bit-flip and corruption detection across transmission paths.
3. Fail-Safe Deterministic Safe State:
   - Switch root uplink failure or heartbeat watchdog timeout (> 200 ms) triggers automatic fail-safe
     fallback, de-energizing safety outputs and asserting %M584 fault alarm.
4. Horner OCS Memory Space Integration:
   - Word registers %R2500..%R2507:
     %R2500: Star Node / Switch Status (High: Node ID, Low: Operational State 0..2)
     %R2501: Star Topology State (1 = HEALTHY, 2 = DEGRADED, 3 = FAULT)
     %R2502: Forwarding Delay / Switch Latency (ms x10, nominal < 2.0 ms)
     %R2503: Root Port State (0 = DOWN, 1 = LINK_UP, 2 = BLOCKED, 3 = FORWARDING)
     %R2504: Active Branch Ports Bitmask (Bits 0..7 for branch ports 1..8)
     %R2505: Rolling Sequence Counter (0..65535)
     %R2506: CRC & Topology Status Word (Bit0=S1, Bit1=S2, Bit2=Star Active, Bit3=Root Up, Bit4=Branches Healthy, Bit5=Switch Root, Bit6=Fail-Safe)
     %R2507: Diagnostic Code (0x0000 OK, 0xEE11..0xEE17)
   - Discrete coils %M583..%M584:
     %M583: Star Topology Active / Healthy (BOOL)
     %M584: Star Topology Fault / Branch Loss Alarm (BOOL)
5. Pure IEC 61131-3 Structured Text (ST) POU:
   - CipSafetyAplStarSync program with register bindings and anti-ladder validation.

Generates:
  artifacts/telemetry/cip_safety_apl_star_evidence.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Union

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_PATH = REPO_ROOT / "src"
for p in (str(REPO_ROOT), str(SRC_PATH)):
    if p not in sys.path:
        sys.path.insert(0, p)

from jev_cscape.telemetry.cip_safety_apl_star import (
    run_cip_safety_apl_star_verification,
)

# ANSI terminal formatting constants matching repo conventions
ESC_RESET = "\033[0m"
ESC_BOLD = "\033[1m"
ESC_DIM = "\033[2m"
ESC_GREEN = "\033[92m"
ESC_RED = "\033[91m"
ESC_YELLOW = "\033[93m"
ESC_CYAN = "\033[96m"


def format_stage_badge(passed: bool, status: Optional[str] = None) -> str:
    """Format strict 4-state contract ANSI badge."""
    norm_status = (status or "").lower()
    if norm_status == "blocked":
        return f"{ESC_YELLOW}{ESC_BOLD}[BLOCKED]{ESC_RESET}"
    if norm_status == "inconclusive":
        return f"{ESC_YELLOW}{ESC_BOLD}[INCONCLUSIVE]{ESC_RESET}"
    if passed or norm_status in ("passed", "pass", "success"):
        return f"{ESC_GREEN}{ESC_BOLD}[PASS]{ESC_RESET}"
    return f"{ESC_RED}{ESC_BOLD}[FAIL]{ESC_RESET}"


def format_stage_result(
    stage: int | str,
    name: str,
    passed: bool,
    timing_ms: Optional[float] = None,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format a single stage line with ANSI colored badge, timing, and description."""
    badge = format_stage_badge(passed, status)
    timing_str = f" ({timing_ms:.3f} ms)" if timing_ms is not None else ""
    line = f"  Stage {stage}: {badge} {name}{timing_str}"
    if details:
        line += f"\n    {ESC_DIM}{details}{ESC_RESET}"
    return line


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute W289 CIP Safety Over Ethernet-APL Star Verification Suite"
    )
    parser.add_argument(
        "positional_path",
        nargs="?",
        default=None,
        help="Optional positional path for output evidence JSON file",
    )
    parser.add_argument(
        "--output",
        "-o",
        dest="flag_path",
        default=None,
        help="Path to output JSON evidence artifact",
    )
    parser.add_argument(
        "--work-package",
        "-w",
        default="W289",
        help="Work package ID (default: W289)",
    )
    args = parser.parse_args(argv)

    selected_path = args.flag_path or args.positional_path
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_apl_star_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print(f"  {ESC_BOLD}JEV Cscape Agent: ODVA CIP Safety Over Ethernet-APL Star Verification ({args.work_package}){ESC_RESET}")
    print("=" * 80)

    try:
        evidence = run_cip_safety_apl_star_verification(
            output_path=str(evidence_path),
            work_package=args.work_package,
        )
    except Exception as exc:
        print(f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:")
        print(f"  {type(exc).__name__}: {exc}")
        print("=" * 80)
        return 1

    stages = evidence.get("data", {}).get("stages") or evidence.get("data", {}).get("tests", [])
    for stg in stages:
        stage_num = stg.get("stage", "?")
        stage_name = stg.get("name") or stg.get("check", "unnamed_stage")
        passed = stg.get("passed", False)
        timing = stg.get("timing_ms")
        details = stg.get("details", "")
        print(format_stage_result(stage_num, stage_name, passed, timing, details))

    passed_count = evidence.get("data", {}).get("checks_passed", sum(1 for s in stages if s.get("passed", False)))
    total_count = evidence.get("data", {}).get("total_checks", len(stages))
    status_str = evidence.get("status", "unknown")

    print("-" * 80)
    status_badge = (
        f"{ESC_GREEN}{ESC_BOLD}{status_str.upper()}{ESC_RESET}"
        if status_str == "success"
        else f"{ESC_RED}{ESC_BOLD}{status_str.upper()}{ESC_RESET}"
    )
    print(f"[*] Outcome: {passed_count}/{total_count} checks passed across {len(stages)} verification stages.")
    print(f"[*] Status: {status_badge}")
    print(f"[*] Evidence artifact saved: {ESC_CYAN}{evidence_path}{ESC_RESET}")
    print("=" * 80)

    # Ensure evidence file was written
    if not evidence_path.exists():
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return 0 if status_str == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
