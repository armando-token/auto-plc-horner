#!/usr/bin/env python3
"""Verification Script for Industrial ODVA CIP Safety Over Ethernet-APL Redundant Trunks Protocol Engine (Wave W277).

Work Package: W277 (Gate G8 Industrial Protocols / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY
Status Contract: Strict 4-State JSON output & evidence emission.

Standards & Specifications:
- IEEE 802.3cg-2019 / Ethernet-APL:
  - Dual 10BASE-T1L Single Pair Ethernet operating at 10 Mb/s full-duplex over redundant balanced twisted pairs.
  - IEC 60079-47 (2-WISE: 2-Wire Intrinsically Safe Ethernet) for Zone 0 / Class I, Div 1 explosive atmospheres:
    - Loop voltage nominal: 12000 mV (12.0 V DC).
    - Intrinsic Safety (IS) permissible bounds: 9600 mV .. 15000 mV (9.6 V .. 15.0 V).
    - Under-voltage droop (< 9600 mV) trips fault 0xEC01 (TRUNK_A_DROOP) or 0xEC02 (TRUNK_B_DROOP).
    - Dual failure trips fault 0xEC03 (DUAL_TRUNK_FAIL).
  - Bumpless switchover latency surveillance:
    - Nominal failover switchover time: < 2500 us (2.5 ms).
    - Switchover latency exceeding 2500 us trips fault 0xEC04 (SWITCHOVER_TIMEOUT).
    - Asynchronous packet sequence divergence trips fault 0xEC05 (SPLIT_BRAIN_SYNC_LOSS).
- ODVA CIP Networks Library Volume 5: CIP Safety Specification (IEC 61784-3-2 / IEC 61508 SIL 3):
  - Dual 16-bit Safety CRCs (CRC-S1 poly 0x5935, CRC-S2 poly 0x755B inverted data).
- Horner OCS Memory Space:
  - Analog registers %R2380..%R2387:
    - %R2380: REG_CIP_SAFETY_REDUNDANT_STATE (0=TRUNK_A_ACTIVE, 1=TRUNK_B_ACTIVE, 2=DUAL_TRACKING, 3=SAFETY_FALLBACK_DEGRADED, 4=TRIP_SHUTDOWN)
    - %R2381: REG_CIP_SAFETY_REDUNDANT_ACTIVE_TRUNK (1=Trunk A, 2=Trunk B, 3=Both synchronized)
    - %R2382: REG_CIP_SAFETY_REDUNDANT_TRUNK_A_VOLTAGE_MV (nominal 12000 mV, IS bounds 9600..15000 mV)
    - %R2383: REG_CIP_SAFETY_REDUNDANT_TRUNK_B_VOLTAGE_MV (nominal 12000 mV, IS bounds 9600..15000 mV)
    - %R2384: REG_CIP_SAFETY_REDUNDANT_SWITCHOVER_COUNT (0..65535 rolling)
    - %R2385: REG_CIP_SAFETY_REDUNDANT_CRC_STATUS (Bit0=Trunk A CRC OK, Bit1=Trunk B CRC OK, Bit2=Seq Synced, 0x0007 nominal)
    - %R2386: REG_CIP_SAFETY_REDUNDANT_LATENCY_US (nominal < 2500 us)
    - %R2387: REG_CIP_SAFETY_REDUNDANT_DIAGNOSTIC_CODE (0x0000=OK, 0xEC01..0xEC05)
  - Discrete coils %M555..%M556:
    - %M555: COIL_CIP_SAFETY_REDUNDANT_ESTABLISHED (BOOL, True when state in (0, 1, 2))
    - %M556: COIL_CIP_SAFETY_REDUNDANT_TRIPPED (BOOL, True when state in (3, 4) or diagnostic != 0)

Follows the deterministic 9-stage verification pattern:
  Stage 1: Enums, Constants & Horner OCS Register Mappings (%R2380..%R2387, %M555..%M556)
  Stage 2: Safe CRC-S1 / CRC-S2 Dual 16-bit Polynomial Calculation & Mutation Detection
  Stage 3: Pure IEC 61131-3 Structured Text POU Validation & Anti-Ladder Construct Rejection Guard
  Stage 4: Nominal Dual Tracking Operation & Register Table Synchronization
  Stage 5: Trunk A Voltage Droop Interception (< 9600 mV) & Bumpless Failover to Trunk B
  Stage 6: Trunk B Voltage Droop Interception (< 9600 mV) & Bumpless Failover to Trunk A
  Stage 7: Dual Trunk Failure Safe Shutdown Interlock & Fault 0xEC03 Trip
  Stage 8: Switchover Latency Jitter Timeout Detection (> 2500 us) & Fault 0xEC04 Trip
  Stage 9: Split-Brain Packet Sequence Divergence Detection & Multi-Cycle Scan Step Execution

Generates:
  artifacts/telemetry/cip_safety_apl_redundant_evidence.json
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
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.telemetry.cip_safety_apl_redundant import (
    run_cip_safety_apl_redundant_verification,
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
    check: str,
    passed: bool,
    timing_ms: Optional[float] = None,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format a single stage line with ANSI colored badge, timing, and description."""
    badge = format_stage_badge(passed, status)
    timing_str = f" ({timing_ms:.2f} ms)" if timing_ms is not None else ""
    line = f"  Stage {stage}: {badge} {check}{timing_str}"
    if details:
        line += f"\n    {ESC_DIM}{details}{ESC_RESET}"
    return line


def run_deterministic_9stage_suite(
    output_path: Optional[Union[str, Path]] = None,
    work_package: str = "W277",
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite for W277.

    Returns strict 4-state contract JSON evidence.
    """
    try:
        return run_cip_safety_apl_redundant_verification(
            output_path=str(output_path) if output_path is not None else None,
            work_package=work_package,
        )
    except TypeError:
        return run_cip_safety_apl_redundant_verification(
            output_path=str(output_path) if output_path is not None else None
        )


def main(argv: Optional[List[str]] = None) -> int:
    """Main verification CLI entry point."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="JEV Cscape Agent: Industrial ODVA CIP Safety Over Ethernet-APL Redundant Trunks Verification (W277)"
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
        help="Specified evidence JSON output path",
    )
    parser.add_argument(
        "--work-package",
        dest="work_package",
        default="W277",
        help="Work package identifier (default: W277)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw strict 4-state contract JSON to stdout",
    )
    args = parser.parse_args(argv)

    selected_path = args.flag_path or args.positional_path
    if selected_path:
        evidence_path = Path(selected_path).resolve()
    else:
        evidence_path = (
            REPO_ROOT
            / "artifacts"
            / "telemetry"
            / "cip_safety_apl_redundant_evidence.json"
        ).resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print("=" * 80)
        print(
            f"  {ESC_BOLD}JEV Cscape Agent: Industrial ODVA CIP Safety Over Ethernet-APL Redundant Trunks Verification ({args.work_package}){ESC_RESET}"
        )
        print("=" * 80)

    t_start = time.perf_counter()
    try:
        evidence = run_deterministic_9stage_suite(
            output_path=evidence_path,
            work_package=args.work_package,
        )
    except Exception as exc:
        elapsed_fail = (time.perf_counter() - t_start) * 1000.0
        fail_payload: Dict[str, Any] = {
            "status": "failed",
            "error_code": "VERIFICATION_EXCEPTION",
            "details": f"Verification suite crashed with unhandled exception: {exc}",
            "stages_passed": 0,
            "total_stages": 9,
            "passed_stages": 0,
            "data": {
                "work_package": args.work_package,
                "duration_ms": elapsed_fail,
                "stages": [],
                "tests": [],
            },
        }
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(fail_payload, f, indent=2)

        if args.json:
            print(json.dumps(fail_payload, indent=2))
        else:
            print(
                f"\n[{ESC_RED}{ESC_BOLD}EXCEPTION{ESC_RESET}] Verification suite crashed with unhandled exception:"
            )
            print(f"  {type(exc).__name__}: {exc}")
            print("=" * 80)
        return 1

    total_elapsed_ms = (time.perf_counter() - t_start) * 1000.0

    # Ensure evidence dictionary has tests alias and total_checks
    if isinstance(evidence, dict) and "data" in evidence:
        stages_list = evidence["data"].get("stages", [])
        if "tests" not in evidence["data"]:
            evidence["data"]["tests"] = stages_list
        if "checks_passed" not in evidence["data"]:
            evidence["data"]["checks_passed"] = sum(
                1 for s in stages_list if s.get("passed")
            )
        if "total_checks" not in evidence["data"]:
            evidence["data"]["total_checks"] = len(stages_list)
        # Re-save with complete data
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    if args.json:
        print(json.dumps(evidence, indent=2))
        return 0 if evidence.get("status") == "success" else 1

    valid_states = {"success", "failed", "blocked", "inconclusive"}
    overall_status = (
        evidence.get("status") if isinstance(evidence, dict) else None
    )
    error_code = (
        evidence.get("error_code")
        if isinstance(evidence, dict)
        else "INVALID_PAYLOAD"
    )
    details_str = (
        evidence.get("details", "")
        if isinstance(evidence, dict)
        else "Evidence is not a dictionary"
    )

    if overall_status not in valid_states:
        print(
            f"\n[{ESC_RED}{ESC_BOLD}CONTRACT VIOLATION{ESC_RESET}] Invalid status '{overall_status}'. Must be one of {valid_states}."
        )
        print("=" * 80)
        return 1

    stages_data: List[Dict[str, Any]] = []
    if isinstance(evidence, dict):
        data_dict = evidence.get("data")
        if isinstance(data_dict, dict):
            stages_data = data_dict.get("stages") or data_dict.get("tests") or []

    print("\nDeterministic 9-Stage Redundant Trunks Protocol Verification Results:")
    for s in stages_data:
        st_num = s.get("stage", "?")
        chk_name = (
            s.get("check")
            or s.get("name")
            or s.get("stage_name")
            or f"Stage_{st_num}"
        )
        passed = bool(s.get("passed"))
        details = s.get("details", "")
        timing = s.get("timing_ms")
        st_stat = s.get("status")
        print(format_stage_result(st_num, chk_name, passed, timing, details, st_stat))

    print("-" * 80)
    print(f"Total Execution Time: {total_elapsed_ms:.2f} ms")
    stages_passed = evidence.get(
        "stages_passed", sum(1 for s in stages_data if s.get("passed"))
    )
    total_stages = evidence.get("total_stages", len(stages_data))
    print(f"Stages Passed: {stages_passed}/{total_stages}")
    print(f"Evidence Artifact: {ESC_CYAN}{evidence_path}{ESC_RESET}")
    print(f"Engineering Contract Status: {overall_status.upper()}")

    if overall_status == "blocked":
        print(
            f"\n{ESC_YELLOW}{ESC_BOLD}[BLOCKED] Action prevented by safety policy or platform limitation: {error_code}{ESC_RESET}"
        )
        return 2
    elif overall_status == "inconclusive":
        print(
            f"\n{ESC_YELLOW}{ESC_BOLD}[INCONCLUSIVE] Outcome unverified: {error_code}{ESC_RESET}"
        )
        return 3
    elif overall_status == "success":
        print(
            f"\n{ESC_GREEN}{ESC_BOLD}[SUCCESS] All 9 CIP Safety Over Ethernet-APL Redundant Trunks protocol stages PASSED deterministically.{ESC_RESET}"
        )
        print("=" * 80)
        return 0
    else:
        print(
            f"\n{ESC_RED}{ESC_BOLD}[FAILED] Verification failed with status '{overall_status}' (error_code: {error_code}).{ESC_RESET}"
        )
        print(f"Details: {details_str}")
        print("=" * 80)
        return 1


if __name__ == "__main__":
    sys.exit(main())
