#!/usr/bin/env python3
"""Verification Script for Industrial ODVA CIP Safety Over Ethernet-APL Trunk / Spur Power Coordination Protocol Engine (Wave W295).

Work Package: W295 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [ODVA CIP Safety Over Ethernet-APL Trunk/Spur Power Coordination]
Status Contract: Strict 4-State JSON output & evidence emission.

Features & Standards:
1. IEEE 802.3cg-2019 / Ethernet-APL Trunk & Spur Power Delivery (PoDL / Power Coordination):
   - Multi-port trunk and spur power supply monitoring and power class negotiation.
   - Intrinsically safe (Ex-i / 2-WISE) power envelope surveillance, voltage/current monitoring, and under-voltage lockout.
2. ODVA CIP Networks Library Volume 5: CIP Safety Specification (IEC 61784-3-2 / IEC 61508 SIL 3):
   - Dual 16-bit Safety CRCs:
     - CRC-S1: 16-bit generator polynomial 0x5935 over payload data.
     - CRC-S2: 16-bit generator polynomial 0x755B over inverted sequence counter, timestamp, and SNN.
   - Bit-flip and corruption detection across power-managed links.
3. Fail-Safe Deterministic Safe State:
   - Power sag, current surge, or under-voltage trip asserting %M598 alarm coil and safe state fallback.
4. Horner OCS Memory Space Integration:
   - Word registers %R2560..%R2567:
     %R2560: Power Node / Trunk Status (High: Node ID, Low: Operational State)
     %R2561: Power Delivery State (1 = HEALTHY, 2 = DEGRADED, 3 = FAULT)
     %R2562: Bus Voltage (mV or nominal 10x V)
     %R2563: Bus Current / Power Consumption (mA or mW)
     %R2564: Power Class & Intrinsically Safe (2-WISE) Status Bitmask
     %R2565: Rolling Sequence Counter (0..65535)
     %R2566: CRC & Power Status Word
     %R2567: Diagnostic Code (0x0000 OK, 0xEE31..0xEE37)
   - Discrete coils %M597..%M598:
     %M597: APL Power Coordination Active / Healthy (BOOL)
     %M598: APL Power Fault / Under-Voltage Alarm (BOOL)
5. Pure IEC 61131-3 Structured Text (ST) POU:
   - CipSafetyAplPowerSync program with register bindings and anti-ladder validation.

Generates:
  artifacts/telemetry/cip_safety_apl_power_evidence.json
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

from jev_cscape.telemetry.cip_safety_apl_power import (
    run_cip_safety_apl_power_verification,
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
        description="Execute W295 CIP Safety Over Ethernet-APL Trunk / Spur Power Coordination Verification Suite"
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
        default="W295",
        help="Work package ID (default: W295)",
    )
    parser.add_argument(
        "--json",
        "--json-only",
        action="store_true",
        help="Emit raw JSON report only (no ANSI stdout banner)",
    )
    args = parser.parse_args(argv)

    selected_path = args.flag_path or args.positional_path
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (REPO_ROOT / "artifacts" / "telemetry" / "cip_safety_apl_power_evidence.json").resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(f"  {ESC_BOLD}JEV Cscape Agent: ODVA CIP Safety Over Ethernet-APL Power Coordination Verification ({args.work_package}){ESC_RESET}")
        print("=" * 80)

    t0 = time.perf_counter()
    try:
        evidence = run_cip_safety_apl_power_verification(
            output_path=str(evidence_path),
            work_package=args.work_package,
        )
    except Exception as exc:
        print(f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:")
        print(f"  {type(exc).__name__}: {exc}")
        print("=" * 80)
        return 1
    elapsed_total_ms = (time.perf_counter() - t0) * 1000.0

    # Ensure evidence file was written
    if not evidence_path.exists() or evidence_path.stat().st_size == 0:
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    if args.json:
        print(json.dumps(evidence, indent=2))
        return 0 if evidence.get("status") == "success" else 1

    stages = evidence.get("data", {}).get("stages") or evidence.get("data", {}).get("tests", [])
    for stg in stages:
        stage_num = stg.get("stage", "?")
        stage_name = stg.get("name") or stg.get("check", "unnamed_stage")
        passed = stg.get("passed", False)
        timing = stg.get("timing_ms") or stg.get("duration_ms")
        details = stg.get("details", "")
        status = stg.get("status")
        print(format_stage_result(stage_num, stage_name, passed, timing, details, status))

    passed_count = evidence.get("data", {}).get("checks_passed", sum(1 for s in stages if s.get("passed", False)))
    total_count = evidence.get("data", {}).get("total_checks", len(stages))
    status_str = evidence.get("status", "unknown")

    print("-" * 80)
    status_badge = (
        f"{ESC_GREEN}{ESC_BOLD}{status_str.upper()}{ESC_RESET}"
        if status_str == "success"
        else f"{ESC_RED}{ESC_BOLD}{status_str.upper()}{ESC_RESET}"
    )
    print(f"[*] Outcome: {passed_count}/{total_count} checks passed across {len(stages)} verification stages (in {elapsed_total_ms:.2f} ms).")
    print(f"[*] Status: {status_badge}")
    print(f"[*] Evidence artifact saved: {ESC_CYAN}{evidence_path}{ESC_RESET}")
    print("=" * 80)

    return 0 if status_str == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
